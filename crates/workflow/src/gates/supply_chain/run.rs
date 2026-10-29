//! The two sandboxes of the gate: the fetch, and the scan.
//!
//! # The fetch
//!
//! [`fetch`] runs in the `fetch_deps` profile, the only one with a network, and only after the
//! decision on every new direct dependency is recorded ([`Plan::may_fetch`]; the function refuses
//! otherwise, so the order is not a convention of the caller). It runs three commands and no
//! other: `cargo --version`, `cargo fetch` and `cargo metadata`. Each passes through the command
//! policy of the profile first, which adds `--locked` and denies a build, a test, a procedural
//! macro and an interpreter (the class `repository_code_in_fetch_deps`). `cargo fetch` and
//! `cargo metadata` read the manifests and download packages; neither compiles, so no `build.rs`
//! and no procedural macro of a package or of the project runs. An install script (`npm`
//! `postinstall`, `setup.py`) cannot run either: the gate never starts a package manager other
//! than cargo, and the command sets of Slice 1 list no npm or pip download command.
//!
//! # The scan
//!
//! [`scan`] runs the audit tool and the SBOM tool in a fresh `verify` sandbox: no network, a
//! read-only workspace of the candidate commit. The advisory database must already be on the
//! image or in a cache the sandbox mounts. A tool that is not there blocks the gate.
//!
//! What the supervisor observed is the evidence. Nothing is read from a file the sandbox wrote
//! except through the standard streams the supervisor captured and redacted.

use std::sync::Arc;
use std::time::Duration;

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::ids::{AttemptId, JobId};
use factory_domain::policy::commands::CommandVerdict;
use factory_domain::policy::{PolicyEngine, SandboxProfileKind};
use factory_domain::redaction::Redactor;
use factory_domain::scope::TenantScope;
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{CommitSha, PathRules, RepoGlob};
use factory_ports::sandbox::{
    CacheMount, ExecArgv, ExecRequest, ExecResult, FixedEnv, Hardening, ImageDigest,
    NetworkAttachment, SandboxError, SandboxLimits, SandboxMounts, SandboxProfile, SandboxSession,
    SandboxSpec, TeardownReason,
};
use factory_ports::workspace::{WorkspaceError, WorkspacePurpose, WorkspaceRequest};

use super::licenses::LicensePolicy;
use super::names::PopularNames;
use super::review::Plan;
use super::tools::{
    self, AUDIT, AUDIT_PROBE, AuditRefused, AuditResult, FETCH, METADATA, PackageMeta, SbomTool,
    Unreadable,
};
use crate::gates::command::{Reading, Role, Verdict, interpret};
use crate::handlers::{StageError, StagePorts};
use crate::stages::validation::VerifySandbox;

/// The `fetch_deps` sandbox, apart from the workspace it mounts.
#[derive(Debug, Clone)]
pub struct FetchSandbox {
    /// The image, pinned by digest.
    pub image: ImageDigest,
    /// Resource limits, within the policy maximum for the `fetch_deps` profile.
    pub limits: SandboxLimits,
    /// The environment the supervisor sets. It holds `CARGO_NET_OFFLINE=false`, which the command
    /// set sets for this profile, because a command cannot carry an environment.
    pub env: FixedEnv,
    /// The security settings of the container.
    pub hardening: Hardening,
    /// The caches to mount. The package cache is writable in this profile only.
    pub caches: Vec<CacheMount>,
    /// The per-job sidecar that relays to the registry hosts and no others.
    pub sidecar: String,
    /// The CPU architecture of the image, as the gate report records it.
    pub arch: String,
}

/// Whether the SBOM is required for this job, and the tool that makes it.
#[derive(Debug, Clone)]
pub struct SbomRule {
    /// True for a release or a high-risk job (`supply_chain.sbom.required_for`).
    pub required: bool,
    /// The tool.
    pub tool: SbomTool,
}

/// The bounds on what the gate runs and reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// How long a version probe may run, in seconds.
    pub probe_timeout_seconds: u64,
    /// How long `cargo fetch` may run, in seconds.
    pub fetch_timeout_seconds: u64,
    /// How long any other command may run, in seconds.
    pub command_timeout_seconds: u64,
    /// How much of each stream the supervisor keeps.
    pub max_output_bytes: u64,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            probe_timeout_seconds: 30,
            fetch_timeout_seconds: 600,
            command_timeout_seconds: 300,
            max_output_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Everything the gate is built from. Nothing in it comes from the repository under work.
#[derive(Clone)]
pub struct SupplyChainConfig {
    /// The evaluators of the security and approval policies.
    pub policy: Arc<PolicyEngine>,
    /// The path rules the workspace adapter classifies paths with.
    pub path_rules: PathRules,
    /// The held-out test globs, present in a verify workspace only.
    pub holdouts: Vec<RepoGlob>,
    /// The fetch sandbox.
    pub fetch: FetchSandbox,
    /// The verify sandbox.
    pub verify: VerifySandbox,
    /// The one redactor of the factory.
    pub redactor: Arc<Redactor>,
    /// The license rule.
    pub licenses: LicensePolicy,
    /// The popular names to measure the distance to.
    pub popular: PopularNames,
    /// The names of the organization's internal packages.
    pub internal_names: Vec<String>,
    /// The SBOM rule.
    pub sbom: SbomRule,
    /// The most whole days old the advisory database may be, as the composition root configures
    /// it. The policy has the last word: the limit that counts is never higher than
    /// `supply_chain.advisory_database.max_age_days`, whatever this says
    /// ([`effective_advisory_db_max_age_days`]). A configuration may lower the limit and never
    /// raise it. A database older than the limit, or of unknown age, blocks the advisory gate.
    pub advisory_db_max_age_days: u64,
    /// Bounds.
    pub bounds: Bounds,
}

/// The limit on the age of the advisory database that a stage built without a policy value falls
/// back on, equal to `maximum-db-staleness = "P7D"` in `deny.toml` and to the value in
/// `policies/security.yaml`. A stage built from policy
/// ([`SupplyChainSettings::from_policy`](crate::stages::validation::SupplyChainSettings::from_policy))
/// takes the policy's value instead.
pub const DEFAULT_ADVISORY_DB_MAX_AGE_DAYS: u64 = 7;

/// The limit on the age of the advisory database that counts: the lower of what the composition
/// root configured and what the policy says. Policy is tightened and never loosened, so a
/// configuration above the policy is ignored.
#[must_use]
pub fn effective_advisory_db_max_age_days(cfg: &SupplyChainConfig) -> u64 {
    cfg.advisory_db_max_age_days
        .min(cfg.policy.dependency.advisory_database_max_age_days())
}

impl std::fmt::Debug for SupplyChainConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupplyChainConfig")
            .field("fetch", &self.fetch.image)
            .field("verify", &self.verify.image)
            .finish_non_exhaustive()
    }
}

/// What the sandbox calls need.
pub struct Io<'a> {
    /// The ports of the stage.
    pub ports: StagePorts<'a>,
    /// The tenant, for reading the artifacts the supervisor stored.
    pub scope: TenantScope,
    /// The configuration.
    pub cfg: &'a SupplyChainConfig,
    /// Trips when the engine cancels the attempt.
    pub cancel: &'a dyn CancelSignal,
    /// The job.
    pub job: JobId,
    /// The attempt the sandbox belongs to.
    pub attempt: AttemptId,
}

/// One command, as the supervisor saw it, with its output where it was read.
#[derive(Debug, Clone)]
pub struct Seen {
    /// The vector that ran.
    pub argv: Vec<String>,
    /// How it ended.
    pub exec: ExecResult,
    /// Standard output, when it was read.
    pub stdout: Option<String>,
}

/// Why a step could not give evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocker {
    /// The category.
    pub code: BlockedCode,
    /// What was missing, as the report names it.
    pub missing: String,
}

impl Blocker {
    fn new(code: BlockedCode, missing: &str) -> Self {
        Self {
            code,
            missing: missing.to_owned(),
        }
    }
}

/// How the fetch ended.
#[derive(Debug, Clone)]
pub enum FetchEnd {
    /// The packages were fetched and described.
    Described(Vec<PackageMeta>),
    /// `cargo fetch` ran and refused: the lockfile does not match the manifests or the registry.
    Refused {
        /// The exit code.
        code: i32,
    },
    /// A step could not give evidence.
    Blocked(Blocker),
}

/// The result of the fetch sandbox.
#[derive(Debug, Clone)]
pub struct Fetched {
    /// The sandbox's name, for the report.
    pub sandbox_id: String,
    /// Every command that ran, in order.
    pub seen: Vec<Seen>,
    /// How it ended.
    pub end: FetchEnd,
}

/// How the audit ended.
#[derive(Debug, Clone)]
pub enum AuditEnd {
    /// No advisory found.
    Clean(AuditResult),
    /// Advisories found.
    Found(AuditResult),
    /// The tool is absent, or its answer cannot be used.
    Blocked(Blocker),
}

/// How the SBOM step ended.
#[derive(Debug, Clone)]
pub enum SbomEnd {
    /// A CycloneDX document was made. It is the standard output artifact of the last command.
    Made,
    /// The tool is absent, or the command policy has no entry for it.
    Unavailable(Blocker),
    /// The tool ran and its output is not a CycloneDX document.
    Unusable(Blocker),
}

/// The result of the verify sandbox.
#[derive(Debug, Clone)]
pub struct Scanned {
    /// The sandbox's name, for the report.
    pub sandbox_id: String,
    /// The commands of the audit, in order.
    pub audit_seen: Vec<Seen>,
    /// The commands of the SBOM tool, in order.
    pub sbom_seen: Vec<Seen>,
    /// The audit.
    pub audit: AuditEnd,
    /// The SBOM.
    pub sbom: SbomEnd,
}

fn workspace_error(error: WorkspaceError) -> StageError {
    match error {
        WorkspaceError::Cancelled => StageError::Cancelled,
        WorkspaceError::UnknownCommit | WorkspaceError::NotFetched => {
            StageError::Blocked(BlockedCode::DependencyUnavailable)
        }
        _ => StageError::Tool,
    }
}

/// The fetch sandbox spec for a workspace. Public so that a test can run what a hostile project
/// would run in a sandbox made exactly like this one.
#[must_use]
pub fn fetch_spec(
    cfg: &SupplyChainConfig,
    job: JobId,
    attempt: AttemptId,
    workspace: factory_ports::workspace::WorkspaceMounts,
) -> SandboxSpec {
    let sandbox = &cfg.fetch;
    SandboxSpec {
        job,
        attempt,
        profile: SandboxProfile::FetchDeps,
        image: sandbox.image.clone(),
        limits: sandbox.limits.clone(),
        network: NetworkAttachment::JobInternal {
            sidecar: sandbox.sidecar.clone(),
        },
        mounts: SandboxMounts {
            workspace,
            caches: sandbox.caches.clone(),
        },
        job_token: None,
        env: sandbox.env.clone(),
        hardening: sandbox.hardening.clone(),
    }
}

/// The verify sandbox spec for a workspace: no network, no job token.
#[must_use]
pub fn verify_spec(
    cfg: &SupplyChainConfig,
    job: JobId,
    attempt: AttemptId,
    workspace: factory_ports::workspace::WorkspaceMounts,
) -> SandboxSpec {
    let sandbox = &cfg.verify;
    SandboxSpec {
        job,
        attempt,
        profile: SandboxProfile::Verify,
        image: sandbox.image.clone(),
        limits: sandbox.limits.clone(),
        network: NetworkAttachment::None,
        mounts: SandboxMounts {
            workspace,
            caches: sandbox.caches.clone(),
        },
        job_token: None,
        env: sandbox.env.clone(),
        hardening: sandbox.hardening.clone(),
    }
}

/// Fetches the locked packages of the candidate and reads which licenses and which build code
/// came in.
///
/// # Errors
/// [`StageError::PolicyDenied`] when a new direct dependency has no recorded decision, a check
/// refused the change, or the dependency set did not change (nothing is fetched then, and no
/// container is made). Otherwise the errors of a sandbox: the environment is missing or unsafe,
/// the call was cancelled, or the host could not make or remove the workspace.
pub async fn fetch(io: &Io<'_>, plan: &Plan, commit: &CommitSha) -> Result<Fetched, StageError> {
    if !plan.may_fetch() {
        return Err(StageError::PolicyDenied);
    }
    let workspace = io
        .ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: io.job,
                attempt: io.attempt,
                base: commit.clone(),
                rules: io.cfg.path_rules.clone(),
                // A `fetch_deps` workspace is writable and there is no purpose of its own: the
                // checkout of an agent workspace is what the profile needs.
                purpose: WorkspacePurpose::Agent,
            },
            io.cancel,
        )
        .await
        .map_err(workspace_error)?;
    let spec = fetch_spec(io.cfg, io.job, io.attempt, workspace.mounts());
    let mut session = match io.ports.sandbox.create_verified(spec, io.cancel).await {
        Ok(session) => session,
        Err(error) => {
            let _ = workspace.dispose().await;
            return Err(StageError::from(error));
        }
    };
    let sandbox_id = session.id().as_str().to_owned();
    let outcome = fetch_steps(&mut *session, io).await;
    let reason = if outcome.is_ok() {
        TeardownReason::Completed
    } else {
        TeardownReason::Failed
    };
    let torn_down = session.stop_and_remove(reason).await;
    let disposed = workspace.dispose().await;
    let (seen, end) = outcome?;
    torn_down.map_err(StageError::from)?;
    disposed.map_err(workspace_error)?;
    Ok(Fetched {
        sandbox_id,
        seen,
        end,
    })
}

async fn fetch_steps(
    session: &mut dyn SandboxSession,
    io: &Io<'_>,
) -> Result<(Vec<Seen>, FetchEnd), StageError> {
    let bounds = io.cfg.bounds;
    let mut seen = Vec::new();
    let version = argv(&["cargo", "--version"]);
    let probe = match observe(
        session,
        io,
        &version,
        secs(bounds.probe_timeout_seconds),
        true,
    )
    .await?
    {
        Ok(probe) => probe,
        Err(_) => return Ok((seen, FetchEnd::Blocked(sandbox_failed()))),
    };
    let probed = interpret(Role::Other, &probe.exec, &Reading::Unreadable);
    seen.push(probe);
    if let Some(blocker) = not_passed(probed, "cargo") {
        return Ok((seen, FetchEnd::Blocked(blocker)));
    }

    let command = match allowed(io, SandboxProfileKind::FetchDeps, &argv(&FETCH)) {
        Ok(command) => command,
        Err(blocker) => return Ok((seen, FetchEnd::Blocked(blocker))),
    };
    let fetched = match observe(
        session,
        io,
        &command,
        secs(bounds.fetch_timeout_seconds),
        false,
    )
    .await?
    {
        Ok(fetched) => fetched,
        Err(_) => return Ok((seen, FetchEnd::Blocked(sandbox_failed()))),
    };
    let verdict = interpret(Role::Other, &fetched.exec, &Reading::Unreadable);
    let code = fetched.exec.exit_code;
    seen.push(fetched);
    match verdict {
        Verdict::Passed => {}
        Verdict::Blocked(why) => {
            return Ok((seen, FetchEnd::Blocked(Blocker::new(why.code, why.missing))));
        }
        Verdict::Failed(_) => {
            return Ok((
                seen,
                FetchEnd::Refused {
                    code: code.unwrap_or(-1),
                },
            ));
        }
    }

    let command = match allowed(io, SandboxProfileKind::FetchDeps, &argv(&METADATA)) {
        Ok(command) => command,
        Err(blocker) => return Ok((seen, FetchEnd::Blocked(blocker))),
    };
    let described = match observe(
        session,
        io,
        &command,
        secs(bounds.command_timeout_seconds),
        true,
    )
    .await?
    {
        Ok(described) => described,
        Err(_) => return Ok((seen, FetchEnd::Blocked(sandbox_failed()))),
    };
    let verdict = interpret(Role::Other, &described.exec, &Reading::Unreadable);
    let stdout = described.stdout.clone();
    let cut = described.exec.stdout_truncated;
    seen.push(described);
    if let Some(blocker) = not_passed(verdict, "cargo metadata") {
        return Ok((seen, FetchEnd::Blocked(blocker)));
    }
    let unreadable = || {
        FetchEnd::Blocked(Blocker::new(
            BlockedCode::ToolProbeFailed,
            "complete and readable output of cargo metadata",
        ))
    };
    let parsed = match stdout.as_deref() {
        Some(text) if !cut => tools::parse_metadata(text),
        _ => Err(Unreadable),
    };
    Ok((
        seen,
        parsed.map_or_else(|_| unreadable(), FetchEnd::Described),
    ))
}

/// Runs the audit and the SBOM tool over the candidate commit in a fresh verify sandbox.
///
/// # Errors
/// [`StageError::PolicyDenied`] when the change is refused, a decision is missing, or the
/// dependency set did not change. Otherwise the errors of a sandbox, as for [`fetch`].
pub async fn scan(io: &Io<'_>, plan: &Plan, commit: &CommitSha) -> Result<Scanned, StageError> {
    if !plan.may_fetch() {
        return Err(StageError::PolicyDenied);
    }
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
    let spec = verify_spec(io.cfg, io.job, io.attempt, workspace.mounts());
    let mut session = match io.ports.sandbox.create_verified(spec, io.cancel).await {
        Ok(session) => session,
        Err(error) => {
            let _ = workspace.dispose().await;
            return Err(StageError::from(error));
        }
    };
    let sandbox_id = session.id().as_str().to_owned();
    let components = usize::from(
        plan.integrity
            .head
            .locks
            .values()
            .flat_map(|lock| &lock.packages)
            .any(|package| package.origin.is_default_registry()),
    );
    let outcome = scan_steps(&mut *session, io, components).await;
    let reason = if outcome.is_ok() {
        TeardownReason::Completed
    } else {
        TeardownReason::Failed
    };
    let torn_down = session.stop_and_remove(reason).await;
    let disposed = workspace.dispose().await;
    let (audit_seen, sbom_seen, audit, sbom) = outcome?;
    torn_down.map_err(StageError::from)?;
    disposed.map_err(workspace_error)?;
    Ok(Scanned {
        sandbox_id,
        audit_seen,
        sbom_seen,
        audit,
        sbom,
    })
}

type ScanSteps = (Vec<Seen>, Vec<Seen>, AuditEnd, SbomEnd);

async fn scan_steps(
    session: &mut dyn SandboxSession,
    io: &Io<'_>,
    components: usize,
) -> Result<ScanSteps, StageError> {
    let (mut audit_seen, mut sbom_seen) = (Vec::new(), Vec::new());
    let audit = audit_step(session, io, &mut audit_seen).await?;
    let sbom = sbom_step(session, io, &mut sbom_seen, components).await?;
    Ok((audit_seen, sbom_seen, audit, sbom))
}

async fn audit_step(
    session: &mut dyn SandboxSession,
    io: &Io<'_>,
    seen: &mut Vec<Seen>,
) -> Result<AuditEnd, StageError> {
    let bounds = io.cfg.bounds;
    // A tool that does not report its version is not there.
    let Some(probe) = probe(session, io, &argv(&AUDIT_PROBE), seen).await? else {
        return Ok(AuditEnd::Blocked(Blocker::new(
            BlockedCode::ToolUnavailable,
            "cargo audit",
        )));
    };
    drop(probe);
    let command = match allowed(io, SandboxProfileKind::Verify, &argv(&AUDIT)) {
        Ok(command) => command,
        Err(blocker) => return Ok(AuditEnd::Blocked(blocker)),
    };
    let ran = match observe(
        session,
        io,
        &command,
        secs(bounds.command_timeout_seconds),
        true,
    )
    .await?
    {
        Ok(ran) => ran,
        Err(_) => return Ok(AuditEnd::Blocked(sandbox_failed())),
    };
    let verdict = interpret(Role::Other, &ran.exec, &Reading::Unreadable);
    let (code, cut, stdout) = (
        ran.exec.exit_code,
        ran.exec.stdout_truncated,
        ran.stdout.clone(),
    );
    seen.push(ran);
    // Only the cases that are not an answer of the tool are decided by `interpret`; an exit code
    // of 1 is the tool's way to say that it found advisories, and its output says which.
    if let Verdict::Blocked(why) = &verdict {
        return Ok(AuditEnd::Blocked(Blocker::new(why.code, why.missing)));
    }
    let unusable = |what: &str| AuditEnd::Blocked(Blocker::new(BlockedCode::ToolProbeFailed, what));
    let Some(text) = stdout.filter(|_| !cut) else {
        return Ok(unusable("complete and readable output of cargo audit"));
    };
    let result = match tools::parse_audit(&text) {
        Ok(result) => result,
        Err(AuditRefused::Configured) => {
            return Ok(unusable(
                "an audit run with the default settings (this one ignored or filtered advisories)",
            ));
        }
        Err(AuditRefused::Unreadable) => {
            return Ok(unusable("output of cargo audit in the form it prints"));
        }
    };
    Ok(match (code, result.count) {
        (Some(0), 0) => AuditEnd::Clean(result),
        (Some(1), count) if count > 0 => AuditEnd::Found(result),
        _ => unusable("output of cargo audit that agrees with its exit code"),
    })
}

async fn sbom_step(
    session: &mut dyn SandboxSession,
    io: &Io<'_>,
    seen: &mut Vec<Seen>,
    components: usize,
) -> Result<SbomEnd, StageError> {
    let bounds = io.cfg.bounds;
    let tool = &io.cfg.sbom.tool;
    let absent =
        |missing: &str| SbomEnd::Unavailable(Blocker::new(BlockedCode::ToolUnavailable, missing));
    // The command policy decides first: a tool it has no entry for cannot run at all.
    let command = match allowed(io, SandboxProfileKind::Verify, &tool.argv) {
        Ok(command) => command,
        Err(blocker) => return Ok(SbomEnd::Unavailable(blocker)),
    };
    if probe(session, io, &tool.probe, seen).await?.is_none() {
        return Ok(absent("the SBOM tool"));
    }
    let ran = match observe(
        session,
        io,
        &command,
        secs(bounds.command_timeout_seconds),
        true,
    )
    .await?
    {
        Ok(ran) => ran,
        Err(_) => return Ok(SbomEnd::Unusable(sandbox_failed())),
    };
    let verdict = interpret(Role::Other, &ran.exec, &Reading::Unreadable);
    let (cut, stdout) = (ran.exec.stdout_truncated, ran.stdout.clone());
    seen.push(ran);
    let unusable = || {
        SbomEnd::Unusable(Blocker::new(
            BlockedCode::ToolProbeFailed,
            "a complete CycloneDX document from the SBOM tool",
        ))
    };
    if let Verdict::Blocked(why) = verdict {
        return Ok(SbomEnd::Unusable(Blocker::new(why.code, why.missing)));
    }
    Ok(match (verdict, stdout) {
        (Verdict::Passed, Some(text)) if !cut && tools::is_cyclonedx(&text, components) => {
            SbomEnd::Made
        }
        _ => unusable(),
    })
}

/// Runs a version probe. `Some` when it exited with code 0; the probe is recorded either way.
async fn probe(
    session: &mut dyn SandboxSession,
    io: &Io<'_>,
    command: &[String],
    seen: &mut Vec<Seen>,
) -> Result<Option<Seen>, StageError> {
    let timeout = secs(io.cfg.bounds.probe_timeout_seconds);
    let Ok(probe) = observe(session, io, command, timeout, true).await? else {
        return Ok(None);
    };
    let passed = matches!(
        interpret(Role::Other, &probe.exec, &Reading::Unreadable),
        Verdict::Passed
    );
    seen.push(probe.clone());
    Ok(passed.then_some(probe))
}

/// Passes a command through the command policy of a profile. The vector that runs is the
/// policy's own, with the forced arguments inserted.
fn allowed(
    io: &Io<'_>,
    profile: SandboxProfileKind,
    command: &[String],
) -> Result<Vec<String>, Blocker> {
    match io.cfg.policy.commands.evaluate(command, profile) {
        CommandVerdict::Allowed(allowed) => Ok(allowed.argv),
        CommandVerdict::RequireHuman { .. } | CommandVerdict::Denied(_) => Err(Blocker::new(
            BlockedCode::PolicyUnresolvable,
            "a command that the command policy allows in this profile",
        )),
    }
}

fn not_passed(verdict: Verdict, tool: &str) -> Option<Blocker> {
    match verdict {
        Verdict::Passed => None,
        Verdict::Blocked(why) => Some(Blocker::new(why.code, why.missing)),
        Verdict::Failed(_) => Some(Blocker::new(BlockedCode::ToolUnavailable, tool)),
    }
}

fn sandbox_failed() -> Blocker {
    Blocker::new(BlockedCode::EnvironmentUnsupported, "a working sandbox")
}

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

fn secs(seconds: u64) -> Duration {
    Duration::from_secs(seconds)
}

/// Runs one command and records what the supervisor saw. The outer error is for the stage; the
/// inner one is the sandbox's own failure, which the caller turns into a blocked step.
async fn observe(
    session: &mut dyn SandboxSession,
    io: &Io<'_>,
    command: &[String],
    timeout: Duration,
    read_stdout: bool,
) -> Result<Result<Seen, SandboxError>, StageError> {
    let vector = ExecArgv::new(command.to_vec()).map_err(|_| StageError::Internal)?;
    let request = ExecRequest {
        argv: vector,
        cwd: None,
        stdin: None,
        timeout,
        max_output_bytes: io.cfg.bounds.max_output_bytes,
    };
    match session.exec(request, io.cancel).await {
        Ok(exec) => {
            let stdout = if read_stdout {
                io.ports
                    .artifacts
                    .get(&io.scope, &exec.stdout)
                    .await
                    .ok()
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            } else {
                None
            };
            Ok(Ok(Seen {
                argv: command.to_vec(),
                exec,
                stdout,
            }))
        }
        Err(SandboxError::Cancelled) => Err(StageError::Cancelled),
        Err(other) => Ok(Err(other)),
    }
}
