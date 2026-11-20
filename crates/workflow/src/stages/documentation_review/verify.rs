//! Running the programs the documentation gate needs, in a fresh verify sandbox.
//!
//! One workspace and one sandbox are made for the stage run: a read-only checkout of the
//! documentation commit, and a new container of the `verify` profile with no network. Neither is
//! the writer's. The commands are the build of the program, its `--help`, each example of the
//! documents and the diagram parser, all as typed argument vectors and never through a shell. What
//! the supervisor returned from `exec` is the evidence.
//!
//! **A tool that is absent is never a pass.** A program that is not in the image, a build that
//! does not finish, a command that is killed or times out, and a sandbox that fails mid-run all
//! become [`Observed::Absent`], which the checks report as `BLOCKED`.

use std::time::Duration;

use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::{AttemptId, JobId};
use factory_domain::scope::TenantScope;
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{CommitSha, PathRules};
use factory_ports::sandbox::{
    ExecArgv, ExecRequest, NetworkAttachment, SandboxError, SandboxMounts, SandboxProfile,
    SandboxSession, SandboxSpec, TeardownReason,
};
use factory_ports::workspace::{WorkspacePurpose, WorkspaceRequest};

use crate::gates::command::{Reading, Role, Verdict, interpret};
use crate::gates::docs::check::{DiagramRun, Needs, Observations, Observed, Ran};
use crate::handlers::{StageError, StagePorts};
use crate::stages::implementation::run::workspace_error;
use crate::stages::validation::VerifySandbox;

/// The commands of the program the documents are about, as data from protected configuration.
#[derive(Debug, Clone)]
pub struct DocsToolchain {
    /// The command that builds the program, such as `cargo build --locked`. Empty when the program
    /// needs no build.
    pub build: Vec<String>,
    /// The path of the built program, relative to the workspace.
    pub binary: String,
    /// The command that parses the diagrams of the documents, run over the workspace. `None` when
    /// the image has no parser, and then a document that holds a diagram is blocked.
    pub diagrams: Option<Vec<String>>,
    /// How long one command may run.
    pub command_timeout_seconds: u64,
    /// How much of each stream of a command the supervisor keeps.
    pub max_output_bytes: u64,
}

/// What the runner needs from the stage.
pub struct Io<'a> {
    /// The ports.
    pub ports: StagePorts<'a>,
    /// The tenant, for reading the streams the supervisor stored.
    pub scope: TenantScope,
    /// The path rules the workspace classifies paths with.
    pub rules: PathRules,
    /// The verify sandbox.
    pub sandbox: &'a VerifySandbox,
    /// The commands.
    pub toolchain: &'a DocsToolchain,
    /// Trips when the engine cancels the attempt.
    pub cancel: &'a dyn CancelSignal,
    /// The job.
    pub job: JobId,
    /// The attempt.
    pub attempt: AttemptId,
}

async fn stream(io: &Io<'_>, reference: &ArtifactRef) -> String {
    match io.ports.artifacts.get(&io.scope, reference).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => String::new(),
    }
}

/// Runs one command. The outer error is for the stage (a cancellation, or a vector that cannot be
/// run at all). `None` is the sandbox's own failure, which the caller turns into a blocked check.
async fn observe(
    session: &mut dyn SandboxSession,
    io: &Io<'_>,
    argv: &[String],
) -> Result<Option<Ran>, StageError> {
    let vector = ExecArgv::new(argv.to_vec()).map_err(|_| StageError::Internal)?;
    let request = ExecRequest {
        argv: vector,
        cwd: None,
        stdin: None,
        timeout: Duration::from_secs(io.toolchain.command_timeout_seconds),
        max_output_bytes: io.toolchain.max_output_bytes,
    };
    match session.exec(request, io.cancel).await {
        Ok(exec) => {
            let stdout = stream(io, &exec.stdout).await;
            let stderr = stream(io, &exec.stderr).await;
            Ok(Some(Ran {
                argv: argv.to_vec(),
                exec,
                stdout,
                stderr,
            }))
        }
        Err(SandboxError::Cancelled) => Err(StageError::Cancelled),
        Err(_) => Ok(None),
    }
}

/// True when the command could not give a result: the program is not there, or it was killed.
fn unusable(ran: &Ran) -> bool {
    matches!(
        interpret(Role::Other, &ran.exec, &Reading::Unreadable),
        Verdict::Blocked(_)
    )
}

/// Makes the workspace and the sandbox, runs what `needs` asks for, and removes both.
///
/// # Errors
/// [`StageError`]: the environment is missing or unsafe, the call was cancelled, or the host could
/// not make or remove the workspace.
pub async fn observe_all(
    io: &Io<'_>,
    commit: &CommitSha,
    needs: &Needs,
) -> Result<Observations, StageError> {
    if !needs.help && needs.examples.is_empty() && needs.diagrams.is_empty() {
        return Ok(Observations::none());
    }
    let workspace = io
        .ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: io.job,
                attempt: io.attempt,
                base: commit.clone(),
                protected_base: None,
                rules: io.rules.clone(),
                purpose: WorkspacePurpose::Verify {
                    holdouts: Vec::new(),
                },
            },
            io.cancel,
        )
        .await
        .map_err(workspace_error)?;
    let spec = SandboxSpec {
        job: io.job,
        attempt: io.attempt,
        profile: SandboxProfile::Verify,
        image: io.sandbox.image.clone(),
        limits: io.sandbox.limits.clone(),
        network: NetworkAttachment::None,
        mounts: SandboxMounts {
            workspace: workspace.mounts(),
            caches: io.sandbox.caches.clone(),
        },
        job_token: None,
        env: io.sandbox.env.clone(),
        hardening: io.sandbox.hardening.clone(),
    };
    let mut session = match io.ports.sandbox.create_verified(spec, io.cancel).await {
        Ok(session) => session,
        Err(error) => {
            let _ = workspace.dispose().await;
            return Err(StageError::from(error));
        }
    };
    let sandbox_id = session.id().as_str().to_owned();
    let outcome = run_all(&mut *session, io, needs).await;
    let reason = if outcome.is_ok() {
        TeardownReason::Completed
    } else {
        TeardownReason::Failed
    };
    let torn_down = session.stop_and_remove(reason).await;
    let disposed = workspace.dispose().await;
    let mut observations = outcome?;
    torn_down.map_err(StageError::from)?;
    disposed.map_err(workspace_error)?;
    observations.sandbox_id = Some(sandbox_id);
    Ok(observations)
}

fn absent<T>(missing: &str) -> Observed<T> {
    Observed::Absent {
        missing: missing.to_owned(),
    }
}

async fn run_all(
    session: &mut dyn SandboxSession,
    io: &Io<'_>,
    needs: &Needs,
) -> Result<Observations, StageError> {
    let mut seen = Observations::none();
    let program_needed = needs.help || !needs.examples.is_empty();
    // The program must build before anything is run against it.
    let mut built = program_needed;
    if program_needed && !io.toolchain.build.is_empty() {
        match observe(session, io, &io.toolchain.build).await? {
            Some(ran) if ran.exec.exit_code == Some(0) && !ran.exec.timed_out => {}
            other => {
                built = false;
                let missing = match &other {
                    Some(ran) if unusable(ran) => {
                        io.toolchain.build.first().cloned().unwrap_or_default()
                    }
                    _ => "the built program".to_owned(),
                };
                if needs.help {
                    seen.help = absent(&missing);
                }
                if !needs.examples.is_empty() {
                    seen.examples = absent(&missing);
                }
            }
        }
    }
    if built {
        let binary = io.toolchain.binary.clone();
        if needs.help {
            seen.help = match observe(session, io, &[binary.clone(), "--help".to_owned()]).await? {
                Some(ran) if unusable(&ran) => absent("the built program"),
                Some(ran) => Observed::Seen(ran),
                None => absent("a working sandbox"),
            };
        }
        if !needs.examples.is_empty() {
            let mut runs = Vec::new();
            let mut gone = false;
            for example in &needs.examples {
                if !example.runnable {
                    runs.push((example.clone(), None));
                    continue;
                }
                let mut argv = vec![binary.clone()];
                argv.extend(example.args.iter().cloned());
                match observe(session, io, &argv).await? {
                    Some(ran) if unusable(&ran) => {
                        gone = true;
                        break;
                    }
                    Some(ran) => runs.push((example.clone(), Some(ran))),
                    None => {
                        gone = true;
                        break;
                    }
                }
            }
            seen.examples = if gone {
                absent("the built program")
            } else {
                Observed::Seen(runs)
            };
        }
    }
    if !needs.diagrams.is_empty() {
        seen.diagrams = match &io.toolchain.diagrams {
            None => absent("a diagram parser"),
            Some(argv) => match observe(session, io, argv).await? {
                Some(ran) if unusable(&ran) => {
                    absent(argv.first().map_or("a diagram parser", String::as_str))
                }
                None => absent("a working sandbox"),
                Some(ran) => Observed::Seen(
                    needs
                        .diagrams
                        .iter()
                        .map(|block| DiagramRun {
                            file: block.file.clone(),
                            line: block.line,
                            ran: ran.clone(),
                        })
                        .collect(),
                ),
            },
        };
    }
    Ok(seen)
}
