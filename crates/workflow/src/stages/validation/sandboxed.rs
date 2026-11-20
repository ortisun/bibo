//! Running the command gates in a fresh verify container.
//!
//! Every call here makes its own workspace and its own sandbox. The workspace is a read-only
//! checkout of one commit with the held-out tests in it, made by the workspace provider on the
//! host, and the sandbox is a new container of the `verify` profile with no network. Neither is
//! the builder's: the builder's container is gone, and nothing it left in `/out` is mounted
//! here. The container and the checkout are removed before the call returns, whatever happened
//! in between.
//!
//! What the supervisor observed is the evidence: the exit code, the signal, the timestamps and
//! the redacted streams that `SandboxSession::exec` returns. A tool that is missing, a sandbox
//! that fails and a command that cannot finish are recorded as such, and never as a pass.

use std::collections::BTreeMap;
use std::time::Duration;

use factory_domain::contracts::gate_report::{BlockedCode, ToolVersion};
use factory_domain::ids::{AttemptId, JobId};
use factory_domain::scope::TenantScope;
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{CommitSha, RepoPath};
use factory_ports::sandbox::{
    ExecArgv, ExecRequest, ExecResult, NetworkAttachment, SandboxError, SandboxMounts,
    SandboxProfile, SandboxSession, SandboxSpec, TeardownReason,
};
use factory_ports::workspace::{WorkspaceError, WorkspacePurpose, WorkspaceRequest};

use super::config::ValidationConfig;
use crate::gates::command::report::tool_version;
use crate::gates::command::{
    CommandGate, Outcomes, Reading, Role, Status, TestReport, Verdict, Why, interpret,
};
use crate::handlers::{StageError, StagePorts};

/// How much of a probe's output is kept.
const PROBE_OUTPUT_BYTES: u64 = 4096;

/// What the sandbox calls need.
pub struct Io<'a> {
    /// The ports of the stage.
    pub ports: StagePorts<'a>,
    /// The tenant, for reading the artifacts the supervisor stored.
    pub scope: TenantScope,
    /// The configuration.
    pub cfg: &'a ValidationConfig,
    /// Trips when the engine cancels the attempt.
    pub cancel: &'a dyn CancelSignal,
    /// The job.
    pub job: JobId,
    /// The attempt the sandbox belongs to.
    pub attempt: AttemptId,
}

/// One command, as the supervisor saw it, with its output where it could be read.
#[derive(Debug, Clone)]
pub struct Seen {
    /// The vector that ran.
    pub argv: Vec<String>,
    /// The directory it ran in.
    pub cwd: Option<String>,
    /// How it ended.
    pub exec: ExecResult,
    /// Standard output, when it was read.
    pub stdout: Option<String>,
    /// Standard error, when it was read.
    pub stderr: Option<String>,
    /// The command that read the test report file back after this command, when the gate names
    /// a report file. Its standard output is the report.
    pub report: Option<Box<Seen>>,
}

impl Seen {
    /// What the gate can read of this command: the two streams for the default format, or the
    /// test report that the gate names.
    #[must_use]
    pub fn reading(&self, report: &TestReport) -> Reading<'_> {
        match report {
            TestReport::Libtest => match (&self.stdout, &self.stderr) {
                (Some(stdout), Some(stderr)) => Reading::Read { stdout, stderr },
                _ => Reading::Unreadable,
            },
            TestReport::Stdout(kind) => match &self.stdout {
                Some(text) => Reading::Report {
                    kind: *kind,
                    text,
                    cut: self.exec.stdout_truncated,
                },
                None => Reading::Unreadable,
            },
            TestReport::File(kind, _) => match self.report.as_deref() {
                // The command that reads the file did not run, or did not end with exit code 0:
                // the file is not there, or it could not be read.
                None => Reading::NoReport,
                Some(read) if read.exec.exit_code != Some(0) || read.exec.timed_out => {
                    Reading::NoReport
                }
                Some(read) => match &read.stdout {
                    Some(text) => Reading::Report {
                        kind: *kind,
                        text,
                        cut: read.exec.stdout_truncated,
                    },
                    None => Reading::Unreadable,
                },
            },
        }
    }
}

/// Why a gate could not run, with the name of what was missing when it is a tool.
#[derive(Debug, Clone)]
pub struct Blocker {
    /// The category and the sentence.
    pub why: Why,
    /// The tool that was missing, such as `cargo clippy`.
    pub tool: Option<String>,
}

/// One gate after it ran, or failed to.
#[derive(Debug, Clone)]
pub struct GateRun {
    /// The gate.
    pub gate: CommandGate,
    /// The version probes that ran for it.
    pub probes: Vec<Seen>,
    /// The tool versions they reported.
    pub versions: Vec<ToolVersion>,
    /// The gate's own command, when it ran.
    pub run: Option<Seen>,
    /// The first, failed run of a test that is in the flaky registry, when it was run again.
    pub first: Option<Seen>,
    /// Why the gate could not run.
    pub blocker: Option<Blocker>,
}

impl GateRun {
    /// The gate's verdict. A gate that could not run is blocked, whatever else is recorded.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        if let Some(blocker) = &self.blocker {
            return Verdict::Blocked(blocker.why.clone());
        }
        match &self.run {
            Some(seen) => interpret(self.gate.role, &seen.exec, &seen.reading(&self.gate.report)),
            None => Verdict::Blocked(Why {
                code: BlockedCode::EnvironmentUnsupported,
                missing: "a run of the gate",
                reason: "The gate did not run, so it gave no result.",
            }),
        }
    }

    /// What the test run showed, for a test gate that ran.
    #[must_use]
    pub fn outcomes(&self) -> Option<Outcomes> {
        self.run.as_ref()?.reading(&self.gate.report).outcomes()
    }
}

/// The result of one sandbox.
#[derive(Debug, Clone)]
pub struct Sandboxed {
    /// The sandbox's name, for the report.
    pub sandbox_id: String,
    /// One entry for each gate, in the order given.
    pub runs: Vec<GateRun>,
}

pub(super) fn workspace_error(error: WorkspaceError) -> StageError {
    match error {
        WorkspaceError::Cancelled => StageError::Cancelled,
        WorkspaceError::UnknownCommit | WorkspaceError::NotFetched => {
            StageError::Blocked(BlockedCode::DependencyUnavailable)
        }
        _ => StageError::Tool,
    }
}

/// Makes a verify workspace of `commit` and a fresh sandbox over it, runs `gates` in it and
/// removes both.
///
/// # Errors
/// [`StageError`]: the environment is missing or unsafe, the call was cancelled, or the host
/// could not make or remove the workspace.
pub async fn in_sandbox(
    io: &Io<'_>,
    commit: &CommitSha,
    gates: &[&CommandGate],
) -> Result<Sandboxed, StageError> {
    let workspace = io
        .ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: io.job,
                attempt: io.attempt,
                base: commit.clone(),
                rules: io.cfg.path_rules.clone(),
                purpose: WorkspacePurpose::Verify {
                    holdouts: io.cfg.holdouts.clone(),
                },
            },
            io.cancel,
        )
        .await
        .map_err(workspace_error)?;
    let sandbox = &io.cfg.sandbox;
    let spec = SandboxSpec {
        job: io.job,
        attempt: io.attempt,
        profile: SandboxProfile::Verify,
        image: sandbox.image.clone(),
        limits: sandbox.limits.clone(),
        network: NetworkAttachment::None,
        mounts: SandboxMounts {
            workspace: workspace.mounts(),
            caches: sandbox.caches.clone(),
        },
        job_token: None,
        mcp_token: None,
        env: sandbox.env.clone(),
        hardening: sandbox.hardening.clone(),
    };
    let mut session = match io.ports.sandbox.create_verified(spec, io.cancel).await {
        Ok(session) => session,
        Err(error) => {
            let _ = workspace.dispose().await;
            return Err(StageError::from(error));
        }
    };
    let sandbox_id = session.id().as_str().to_owned();
    let outcome = run_all(&mut *session, io, gates).await;
    let reason = if outcome.is_ok() {
        TeardownReason::Completed
    } else {
        TeardownReason::Failed
    };
    let torn_down = session.stop_and_remove(reason).await;
    let disposed = workspace.dispose().await;
    let runs = outcome?;
    torn_down.map_err(StageError::from)?;
    disposed.map_err(workspace_error)?;
    Ok(Sandboxed { sandbox_id, runs })
}

type Probe = Result<(Seen, ToolVersion), (Option<Seen>, Blocker)>;

async fn run_all(
    session: &mut dyn SandboxSession,
    io: &Io<'_>,
    gates: &[&CommandGate],
) -> Result<Vec<GateRun>, StageError> {
    let mut probes: BTreeMap<Vec<String>, Probe> = BTreeMap::new();
    let wanted: std::collections::BTreeSet<Vec<String>> =
        gates.iter().flat_map(|gate| gate.probes()).collect();
    for argv in wanted {
        let result = run_probe(session, io, &argv).await?;
        probes.insert(argv, result);
    }
    let mut runs = Vec::with_capacity(gates.len());
    for gate in gates {
        runs.push(run_gate(session, io, gate, &probes).await?);
    }
    Ok(runs)
}

async fn run_probe(
    session: &mut dyn SandboxSession,
    io: &Io<'_>,
    argv: &[String],
) -> Result<Probe, StageError> {
    let tool = argv
        .get(..argv.len().saturating_sub(1))
        .map(|words| words.join(" "));
    let blocker = |why: Why| Blocker {
        why,
        tool: tool.clone(),
    };
    let timeout = Duration::from_secs(io.cfg.bounds.probe_timeout_seconds);
    let seen = match observe(session, io, argv, None, timeout, PROBE_OUTPUT_BYTES, true).await? {
        Ok(seen) => seen,
        Err(_) => return Ok(Err((None, blocker(sandbox_failed())))),
    };
    let blocked = match interpret(Role::Other, &seen.exec, &Reading::Unreadable) {
        Verdict::Passed => None,
        Verdict::Blocked(why) => Some(why),
        Verdict::Failed(_) => Some(Why {
            code: BlockedCode::ToolProbeFailed,
            missing: "a tool that reports its version",
            reason: "The tool did not report its version, so the gate could not run.",
        }),
    };
    if let Some(why) = blocked {
        return Ok(Err((Some(seen), blocker(why))));
    }
    match seen.stdout.as_deref().map(tool_version) {
        Some(Ok(version)) => Ok(Ok((seen, version))),
        _ => Ok(Err((
            Some(seen),
            blocker(Why {
                code: BlockedCode::ToolProbeFailed,
                missing: "a readable tool version",
                reason: "The version of the tool could not be read, so the gate could not run.",
            }),
        ))),
    }
}

fn sandbox_failed() -> Why {
    Why {
        code: BlockedCode::EnvironmentUnsupported,
        missing: "a working sandbox",
        reason: "The sandbox failed while the command ran, so the gate gave no result.",
    }
}

async fn run_gate(
    session: &mut dyn SandboxSession,
    io: &Io<'_>,
    gate: &CommandGate,
    probes: &BTreeMap<Vec<String>, Probe>,
) -> Result<GateRun, StageError> {
    let mut run = GateRun {
        gate: gate.clone(),
        probes: Vec::new(),
        versions: Vec::new(),
        run: None,
        first: None,
        blocker: None,
    };
    for argv in gate.probes() {
        match probes.get(&argv) {
            Some(Ok((seen, version))) => {
                run.probes.push(seen.clone());
                if !run.versions.iter().any(|v| v.tool == version.tool) {
                    run.versions.push(version.clone());
                }
            }
            Some(Err((seen, blocker))) => {
                run.probes.extend(seen.clone());
                run.blocker.get_or_insert_with(|| blocker.clone());
            }
            None => {
                run.blocker.get_or_insert_with(|| Blocker {
                    why: sandbox_failed(),
                    tool: None,
                });
            }
        }
    }
    if run.blocker.is_some() {
        return Ok(run);
    }
    let read_text = gate.role.expects_tests();
    let first = match observe_gate(session, io, gate, read_text).await? {
        Ok(seen) => seen,
        Err(_) => {
            run.blocker = Some(Blocker {
                why: sandbox_failed(),
                tool: None,
            });
            return Ok(run);
        }
    };
    if retry_allowed(io, gate, &first) {
        // One recorded retry, only because every failed test is in the central flaky registry.
        match observe_gate(session, io, gate, read_text).await? {
            Ok(second) => {
                run.first = Some(first);
                run.run = Some(second);
            }
            Err(_) => {
                run.blocker = Some(Blocker {
                    why: sandbox_failed(),
                    tool: None,
                });
            }
        }
    } else {
        run.run = Some(first);
    }
    Ok(run)
}

/// Runs the command of a gate and, when the gate names a test report file, reads the file back
/// with a second command in the same sandbox.
///
/// The report is read only after a test command that ended by itself. The read is an ordinary
/// observed command: its output is redacted, stored and cut at the same size limit, and a file
/// that is absent makes the command fail, which the verdict reads as a missing report.
async fn observe_gate(
    session: &mut dyn SandboxSession,
    io: &Io<'_>,
    gate: &CommandGate,
    read_text: bool,
) -> Result<Result<Seen, SandboxError>, StageError> {
    let mut seen = match observe(
        session,
        io,
        &gate.argv,
        gate.cwd.as_ref(),
        gate.timeout,
        io.cfg.bounds.max_output_bytes,
        read_text,
    )
    .await?
    {
        Ok(seen) => seen,
        Err(error) => return Ok(Err(error)),
    };
    let ended_by_itself = seen.exec.exit_code.is_some() && !seen.exec.timed_out;
    if let (Some(argv), true) = (gate.report_command(), ended_by_itself) {
        let timeout = Duration::from_secs(io.cfg.bounds.probe_timeout_seconds);
        let limit = io.cfg.bounds.max_output_bytes;
        match observe(session, io, &argv, None, timeout, limit, true).await? {
            Ok(read) => seen.report = Some(Box::new(read)),
            Err(error) => return Ok(Err(error)),
        }
    }
    Ok(Ok(seen))
}

/// True when the run failed, and every test that failed is in the central flaky registry.
fn retry_allowed(io: &Io<'_>, gate: &CommandGate, seen: &Seen) -> bool {
    if !gate.role.expects_tests() || io.cfg.flaky_registry.is_empty() {
        return false;
    }
    if !matches!(
        interpret(gate.role, &seen.exec, &seen.reading(&gate.report)),
        Verdict::Failed(_)
    ) {
        return false;
    }
    let Some(outcomes) = seen.reading(&gate.report).outcomes() else {
        return false;
    };
    let failed = outcomes.ids(Status::Failed);
    outcomes.is_consistent()
        && !failed.is_empty()
        && failed.iter().all(|id| io.cfg.flaky_registry.contains(*id))
}

async fn text(io: &Io<'_>, reference: &factory_domain::contracts::ArtifactRef) -> Option<String> {
    let bytes = io.ports.artifacts.get(&io.scope, reference).await.ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Runs one command and records what the supervisor saw.
///
/// The outer error is for the stage: a cancellation, or a vector that cannot be run at all. The
/// inner error is the sandbox's own failure, which the caller turns into a blocked gate.
async fn observe(
    session: &mut dyn SandboxSession,
    io: &Io<'_>,
    argv: &[String],
    cwd: Option<&RepoPath>,
    timeout: Duration,
    max_output_bytes: u64,
    read_text: bool,
) -> Result<Result<Seen, SandboxError>, StageError> {
    let vector = ExecArgv::new(argv.to_vec()).map_err(|_| StageError::Internal)?;
    let request = ExecRequest {
        argv: vector,
        cwd: cwd.cloned(),
        stdin: None,
        timeout,
        max_output_bytes,
    };
    match session.exec(request, io.cancel).await {
        Ok(exec) => {
            let (stdout, stderr) = if read_text {
                (text(io, &exec.stdout).await, text(io, &exec.stderr).await)
            } else {
                (None, None)
            };
            Ok(Ok(Seen {
                argv: argv.to_vec(),
                cwd: cwd.map(|dir| dir.as_str().to_owned()),
                exec,
                stdout,
                stderr,
                report: None,
            }))
        }
        Err(SandboxError::Cancelled) => Err(StageError::Cancelled),
        Err(other) => Ok(Err(other)),
    }
}
