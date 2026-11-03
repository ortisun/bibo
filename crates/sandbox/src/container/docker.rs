//! The Docker command line, as typed calls over the [`ProcessRunner`] port.
//!
//! Every `docker` the crate starts goes through [`DockerClient::run`], which builds a
//! [`SpawnRequest`] with the program [`Program::Docker`], the arguments as an array (no shell, no
//! string splicing), a timeout and an output cap. The runner is the port, so a unit test plugs in
//! a scripted one and the end-to-end tests plug in the real one behind a recorder shim.
//!
//! Nothing here keeps what `docker` prints. Failures come back as [`DockerError`], which carries
//! the exit code and a short, redacted piece of standard error for the log, and nothing else.

use std::sync::Arc;
use std::time::Duration;

use factory_domain::redaction::Redactor;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::process::{
    EnvValue, ProcessRunner, Program, SpawnError, SpawnOutput, SpawnRequest, SpawnStep,
};

use crate::race::BoxFuture;

/// How a control command to the daemon is run. The values are the adapter's configuration; none
/// is a secret.
#[derive(Debug, Clone)]
pub struct DockerSettings {
    /// Environment names and values for the `docker` client, such as `DOCKER_HOST` or
    /// `DOCKER_CONFIG`. The runner clears everything else.
    pub env: Vec<(String, String)>,
    /// How long one control command (`create`, `inspect`, `start`, `rm`, ...) may take.
    pub command_timeout: Duration,
    /// How many bytes of standard output and of standard error a control command may return.
    pub output_cap: u64,
}

impl Default for DockerSettings {
    fn default() -> Self {
        Self {
            env: Vec::new(),
            command_timeout: Duration::from_secs(60),
            output_cap: 4 * 1024 * 1024,
        }
    }
}

/// What `docker` printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerOutput {
    /// The exit code, when the client exited by itself.
    pub code: Option<i32>,
    /// The signal that ended the client.
    pub signal: Option<i32>,
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: Vec<u8>,
    /// True when either stream was cut at the cap.
    pub truncated: bool,
}

impl DockerOutput {
    /// True for exit code 0.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// Why a `docker` call did not give an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerError {
    /// The client is not installed or the daemon cannot be reached.
    Unavailable,
    /// The call ran past its timeout and the client was killed.
    Timeout,
    /// The caller cancelled.
    Cancelled,
    /// The daemon refused or failed the command.
    Failed {
        /// The exit code.
        code: Option<i32>,
        /// What `docker` said, redacted and cut short. Safe to log.
        message: String,
    },
    /// The operating system failed while running the client.
    Os,
}

impl DockerError {
    /// True when the daemon said the container or network does not exist.
    #[must_use]
    pub fn is_missing_object(&self) -> bool {
        matches!(self, Self::Failed { message, .. }
            if message.contains("No such container")
                || message.contains("No such network")
                || message.contains("No such object")
                || message.contains("No such image")
                || message.contains(" not found"))
    }
}

/// The text a client prints when the daemon cannot be reached. The first four are the wording of
/// older clients; the last is the one of the client that prints `failed to connect to the docker
/// API at <address>; check if the path is correct and if the daemon is running` (Docker 29).
fn daemon_unreachable(text: &str) -> bool {
    [
        "Cannot connect to the Docker daemon",
        "Is the docker daemon running",
        "error during connect",
        "Cannot connect to the Docker API",
        "failed to connect to the docker API at",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

/// A cancel signal that is never set. Cleanup runs under it, so a caller's cancel cannot stop the
/// removal of what a cancelled call made.
#[derive(Debug, Clone, Copy, Default)]
pub struct NeverCancel;

impl CancelSignal for NeverCancel {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn is_cancelled(&self) -> bool {
        false
    }

    // The signature `#[async_trait]` would write; see `crate::race`.
    fn cancelled<'life0, 'async_trait>(&'life0 self) -> BoxFuture<'async_trait, ()>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(std::future::pending::<()>())
    }
}

/// Typed access to the `docker` client through the process port.
#[derive(Clone)]
pub struct DockerClient {
    runner: Arc<dyn ProcessRunner>,
    settings: DockerSettings,
    redactor: Arc<Redactor>,
}

impl std::fmt::Debug for DockerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerClient")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl DockerClient {
    /// A client that runs `docker` through `runner`. `redactor` cleans what is logged.
    #[must_use]
    pub fn new(
        runner: Arc<dyn ProcessRunner>,
        settings: DockerSettings,
        redactor: Arc<Redactor>,
    ) -> Self {
        Self {
            runner,
            settings,
            redactor,
        }
    }

    /// The redactor that cleans logged text.
    #[must_use]
    pub fn redactor(&self) -> &Arc<Redactor> {
        &self.redactor
    }

    /// Redacts `bytes` and cuts the result to a length that is safe to log.
    #[must_use]
    pub fn safe_text(&self, bytes: &[u8]) -> String {
        let text = match self.redactor.redact(bytes) {
            Ok(clean) => String::from_utf8_lossy(&clean.output).into_owned(),
            // The policy says to drop the content when the redactor fails.
            Err(_) => return "<withheld: redaction failed>".to_owned(),
        };
        let mut short: String = text.chars().take(400).collect();
        if text.chars().count() > 400 {
            short.push_str("...");
        }
        short
    }

    /// Runs `docker <args>` and returns whatever it printed, whatever its exit code.
    ///
    /// # Errors
    /// [`DockerError::Unavailable`] when there is no client or no daemon, and the timeout,
    /// cancel and operating system failures of the process port.
    pub async fn run_raw(
        &self,
        args: Vec<String>,
        stdin: Option<Vec<u8>>,
        timeout: Duration,
        output_cap: u64,
        cancel: &dyn CancelSignal,
    ) -> Result<DockerOutput, DockerError> {
        let request = SpawnRequest {
            program: Program::Docker,
            args,
            cwd: None,
            env: self
                .settings
                .env
                .iter()
                .map(|(name, value)| (name.clone(), EnvValue::Plain(value.clone())))
                .collect(),
            stdin,
            timeout,
            max_output_bytes: output_cap,
        };
        let SpawnOutput {
            exit_code,
            signal,
            stdout,
            stderr,
            truncated,
        } = self
            .runner
            .run(request, cancel)
            .await
            .map_err(|error| match error {
                SpawnError::ProgramMissing(_) => DockerError::Unavailable,
                SpawnError::Timeout => DockerError::Timeout,
                SpawnError::Cancelled => DockerError::Cancelled,
                SpawnError::Os(SpawnStep::Start) => DockerError::Unavailable,
                SpawnError::Os(_) => DockerError::Os,
            })?;
        if exit_code != Some(0) && daemon_unreachable(&String::from_utf8_lossy(&stderr)) {
            return Err(DockerError::Unavailable);
        }
        Ok(DockerOutput {
            code: exit_code,
            signal,
            stdout,
            stderr,
            truncated,
        })
    }

    /// Runs a control command and requires exit code 0.
    ///
    /// # Errors
    /// As [`run_raw`](Self::run_raw), and [`DockerError::Failed`] for a non-zero exit.
    pub async fn run(
        &self,
        args: Vec<String>,
        cancel: &dyn CancelSignal,
    ) -> Result<DockerOutput, DockerError> {
        self.run_with_input(args, None, cancel).await
    }

    /// Like [`run`](Self::run), with bytes on standard input.
    ///
    /// # Errors
    /// As [`run`](Self::run).
    pub async fn run_with_input(
        &self,
        args: Vec<String>,
        stdin: Option<Vec<u8>>,
        cancel: &dyn CancelSignal,
    ) -> Result<DockerOutput, DockerError> {
        let output = self
            .run_raw(
                args,
                stdin,
                self.settings.command_timeout,
                self.settings.output_cap,
                cancel,
            )
            .await?;
        if output.success() {
            Ok(output)
        } else {
            Err(DockerError::Failed {
                code: output.code,
                message: self.safe_text(&output.stderr),
            })
        }
    }

    /// `docker version`: the platform of the daemon as `os/arch`, such as `linux/arm64`. This is
    /// the probe that tells a stopped daemon from a working one.
    ///
    /// # Errors
    /// [`DockerError`]; `Unavailable` when the daemon does not answer.
    pub async fn server_platform(&self, cancel: &dyn CancelSignal) -> Result<String, DockerError> {
        let output = self
            .run(
                vec![
                    "version".to_owned(),
                    "--format".to_owned(),
                    "{{.Server.Os}}/{{.Server.Arch}}".to_owned(),
                ],
                cancel,
            )
            .await?;
        let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if text.contains('/') && !text.is_empty() {
            Ok(text)
        } else {
            Err(DockerError::Unavailable)
        }
    }

    /// `docker image inspect`: the image id, when the image is on this host.
    ///
    /// # Errors
    /// [`DockerError`]; a missing image is `Failed` with [`DockerError::is_missing_object`].
    pub async fn image_id(
        &self,
        reference: &str,
        cancel: &dyn CancelSignal,
    ) -> Result<String, DockerError> {
        let output = self
            .run(
                vec![
                    "image".to_owned(),
                    "inspect".to_owned(),
                    "--format".to_owned(),
                    "{{.Id}}".to_owned(),
                    reference.to_owned(),
                ],
                cancel,
            )
            .await?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// `docker inspect` of a container or network: the first object of the answer.
    ///
    /// # Errors
    /// [`DockerError`]; an answer that is not one JSON object is `Os`.
    pub async fn inspect(
        &self,
        kind: &str,
        name: &str,
        cancel: &dyn CancelSignal,
    ) -> Result<serde_json::Value, DockerError> {
        let output = self
            .run(
                vec![
                    "inspect".to_owned(),
                    "--type".to_owned(),
                    kind.to_owned(),
                    name.to_owned(),
                ],
                cancel,
            )
            .await?;
        let mut documents: Vec<serde_json::Value> =
            serde_json::from_slice(&output.stdout).map_err(|_| DockerError::Os)?;
        if documents.len() == 1 {
            Ok(documents.remove(0))
        } else {
            Err(DockerError::Os)
        }
    }
}

#[cfg(test)]
mod tests {
    //! What the client says when it cannot reach the daemon. Each test hands the client one text of
    //! standard error, as a scripted `docker` that exits with code 1, and asks what the call became.

    use super::*;
    use factory_domain::redaction::Redactor;
    use factory_ports::process::{ProcessRunner, SpawnOutput};

    /// A runner whose `docker` always exits with code 1 and prints `text` on standard error.
    struct Prints(&'static str);

    #[async_trait::async_trait]
    impl ProcessRunner for Prints {
        fn fidelity(&self) -> Fidelity {
            Fidelity::Fake
        }

        async fn run(
            &self,
            _req: SpawnRequest,
            _cancel: &dyn CancelSignal,
        ) -> Result<SpawnOutput, SpawnError> {
            Ok(SpawnOutput {
                exit_code: Some(1),
                signal: None,
                stdout: Vec::new(),
                stderr: self.0.as_bytes().to_vec(),
                truncated: false,
            })
        }
    }

    async fn what_became_of(stderr: &'static str) -> Result<DockerOutput, DockerError> {
        let client = DockerClient::new(
            Arc::new(Prints(stderr)),
            DockerSettings::default(),
            Arc::new(Redactor::builder().build().expect("a redactor")),
        );
        client
            .run_raw(
                vec!["version".to_owned()],
                None,
                Duration::from_secs(5),
                1024,
                &NeverCancel,
            )
            .await
    }

    async fn is_unavailable(stderr: &'static str) -> bool {
        what_became_of(stderr).await == Err(DockerError::Unavailable)
    }

    #[tokio::test]
    async fn the_phrase_cannot_connect_to_the_docker_daemon_means_unavailable() {
        assert!(
            is_unavailable("Cannot connect to the Docker daemon at unix:///var/run/docker.sock\n")
                .await
        );
    }

    #[tokio::test]
    async fn the_phrase_is_the_docker_daemon_running_means_unavailable() {
        assert!(is_unavailable("error: Is the docker daemon running?\n").await);
    }

    #[tokio::test]
    async fn the_phrase_error_during_connect_means_unavailable() {
        assert!(
            is_unavailable("error during connect: Get \"http://docker.example/v1.45/info\": EOF\n")
                .await
        );
    }

    #[tokio::test]
    async fn the_phrase_cannot_connect_to_the_docker_api_means_unavailable() {
        assert!(is_unavailable("Cannot connect to the Docker API at tcp://127.0.0.1:2375\n").await);
    }

    /// The wording of the client that prints `failed to connect to the docker API at ...` (Docker
    /// 29.9.2 prints it for a `DOCKER_HOST` whose socket is not there).
    #[tokio::test]
    async fn the_current_client_wording_failed_to_connect_to_the_docker_api_means_unavailable() {
        assert!(
            is_unavailable(
                "failed to connect to the docker API at unix:///nonexistent/docker.sock; check if the path is correct and if the daemon is running: dial unix /nonexistent/docker.sock: connect: no such file or directory\n"
            )
            .await
        );
    }

    /// A refusal by a daemon that is there is not an unreachable daemon: the call fails with the
    /// message, and a missing object stays recognisable.
    #[tokio::test]
    async fn a_daemon_that_answers_with_an_error_is_not_unavailable() {
        let refused = what_became_of("Error response from daemon: No such container: gone\n").await;
        assert_eq!(refused.expect("the output is returned").code, Some(1));
        for text in [
            "Error response from daemon: conflict: unable to delete image\n",
            "failed to create the container: name is already in use\n",
        ] {
            assert!(!is_unavailable(text).await, "{text}");
        }
    }
}
