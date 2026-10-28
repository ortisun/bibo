//! The Codex adapter (`codex-cli`).
//!
//! Codex runs inside the `agent` sandbox with `codex exec --json`, the prompt on standard input.
//! The adapter builds the command (`argv`), starts it through the sandbox session, reads the event
//! stream (`events`) and reports what happened.
//!
//! What differs from Claude Code, and why (spike sections 4.3 to 4.8):
//!
//! * **Provider.** Codex ignores `OPENAI_BASE_URL`, so the command carries a custom provider entry
//!   that points at the broker and reads the job token file with an `auth` command.
//! * **Turns.** Codex has no turn cap and no budget flag. The broker counts requests and cuts the
//!   token; the soft deadline of the wall clock is the only limit the adapter sets itself.
//! * **Retries.** Codex retries a lost connection forever by default. The adapter disables that and
//!   caps the provider's retry counts.
//! * **Repository instructions.** `AGENTS.md` is loaded by default and the "ignore" flags do not stop
//!   it, so `project_doc_max_bytes=0` is always set.
//! * **Skills.** Codex reads the repository's `.agents/skills`. The sandbox spec hides the denied
//!   skill directories behind read-only overlays; before every run the adapter lists the skills the
//!   tool can see (`codex debug prompt-input`, no model call) and refuses to start when the list is
//!   not exactly what the stage allows.
//! * **Cost.** Codex reports tokens and no cost. The adapter reports a cost of zero; the broker's
//!   meter is the truth.

pub mod argv;
pub mod events;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{
    AgentRunError, AgentRunReport, AgentRunRequest, AgentRuntime, Capability,
    CapabilityObservation, Denial, ExitInfo, FlagSet, ProbeError, ProbeStep, RuntimeCapabilities,
    RuntimeId,
};
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{ExecResult, SandboxSession};

use crate::command::{EnvName, HARD_DEADLINE_MARGIN_SECONDS, ToolCommand, ToolEnv, broker_origin};
use crate::future::BoxFuture;
use crate::home::{HomeAllocator, make_home_argv};
use crate::io::RunIo;
use crate::probe::{
    ProbeCache, accept_version, capabilities, has_flag, observation, parse_version,
    run_probe_command,
};
use crate::prompt;
use crate::report::{
    ExecEnd, RunEnd, assemble, capture_floor, early, exec_tool, exit_info, soft_deadline_passed,
    usage_of,
};
use crate::target::VerifiedTarget;

/// The runtime's name in manifests and routing.
pub const RUNTIME_NAME: &str = "codex-cli";

/// The version the spike tested.
pub const PINNED_VERSION: &str = "0.163.0";

/// Where the image puts the tool.
pub const DEFAULT_BINARY: &str = "/opt/codex/bin/codex";

/// How the adapter is set up. The defaults match the pinned image.
#[derive(Debug, Clone)]
pub struct CodexConfig {
    /// The path of the tool inside the image.
    pub binary: String,
    /// The versions a stage may run on. Anything else is BLOCKED.
    pub accepted_versions: Vec<String>,
    /// The `PATH` the tool starts with. It includes the directory of Codex's helper programs.
    pub path: String,
    /// The directory under which every run's home is made. The scratch tmpfs.
    pub home_root: String,
    /// How many times the provider retries a failed request and a dropped stream.
    pub retries: u32,
    /// How many bytes of standard output are kept at most. The stream is the transcript.
    pub transcript_cap_bytes: u64,
    /// The skills the specification stage may see. `None` makes that stage unavailable.
    pub spec_skills: Option<Vec<String>>,
}

impl Default for CodexConfig {
    fn default() -> Self {
        Self {
            binary: DEFAULT_BINARY.to_owned(),
            accepted_versions: vec![PINNED_VERSION.to_owned()],
            path: "/opt/codex/codex-path:/opt/codex/bin:/usr/local/bin:/usr/bin:/bin".to_owned(),
            home_root: "/tmp".to_owned(),
            retries: 1,
            transcript_cap_bytes: 16 * 1024 * 1024,
            spec_skills: None,
        }
    }
}

/// The Codex runtime.
pub struct CodexRuntime {
    id: RuntimeId,
    config: CodexConfig,
    io: RunIo,
    cache: ProbeCache,
    homes: HomeAllocator,
    runs: AtomicU64,
}

impl std::fmt::Debug for CodexRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexRuntime")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl CodexRuntime {
    /// Makes the runtime.
    ///
    /// # Panics
    /// Never in practice: the runtime name is a valid slug.
    #[must_use]
    pub fn new(config: CodexConfig, io: RunIo) -> Self {
        let homes = HomeAllocator::new(&config.home_root);
        Self {
            id: RuntimeId::new(RUNTIME_NAME).expect("the runtime name is a valid slug"),
            config,
            io,
            cache: ProbeCache::default(),
            homes,
            runs: AtomicU64::new(0),
        }
    }

    /// How many runs this adapter has started.
    #[must_use]
    pub fn runs_started(&self) -> u64 {
        self.runs.load(Ordering::SeqCst)
    }

    fn short_argv(&self, home: &str, args: Vec<String>) -> Result<Vec<String>, ProbeError> {
        let env = ToolEnv::new()
            .set(EnvName::Home, home)
            .and_then(|env| env.set(EnvName::Path, self.config.path.clone()))
            .map_err(|_| ProbeError::ProbeFailed(ProbeStep::Version))?;
        Ok(ToolCommand {
            env,
            soft_deadline_seconds: 0,
            program: self.config.binary.clone(),
            args,
        }
        .into_probe_argv())
    }

    fn probe_argv(&self, args: &[&str]) -> Result<Vec<String>, ProbeError> {
        self.short_argv(
            &self.config.home_root,
            args.iter().map(|a| (*a).to_owned()).collect(),
        )
    }

    async fn probe_inner(
        &self,
        session: &mut dyn SandboxSession,
    ) -> Result<RuntimeCapabilities, ProbeError> {
        let version_out = run_probe_command(
            session,
            &self.io,
            self.probe_argv(&["--version"])?,
            ProbeStep::Version,
        )
        .await?;
        if version_out.exit_code != Some(0) {
            return Err(ProbeError::ProbeFailed(ProbeStep::Version));
        }
        let version = accept_version(
            parse_version(&version_out.stdout),
            &self.config.accepted_versions,
        )?;
        let help = run_probe_command(
            session,
            &self.io,
            self.probe_argv(&["exec", "--help"])?,
            ProbeStep::Help,
        )
        .await?;
        if help.exit_code != Some(0) {
            return Err(ProbeError::ProbeFailed(ProbeStep::Help));
        }
        let features = run_probe_command(
            session,
            &self.io,
            self.probe_argv(&["features", "list"])?,
            ProbeStep::Trial,
        )
        .await?;
        if features.exit_code != Some(0) {
            return Err(ProbeError::ProbeFailed(ProbeStep::Trial));
        }
        Ok(capabilities(
            version.clone(),
            observations(&help.stdout, &features.stdout, &version),
        ))
    }

    async fn capabilities_for(
        &self,
        session: &mut dyn SandboxSession,
    ) -> Result<RuntimeCapabilities, ProbeError> {
        let image = session.posture().image.clone();
        if let Some(found) = self.cache.recall(&image) {
            return Ok(found);
        }
        let found = self.probe_inner(session).await?;
        self.cache.remember(&image, &found);
        Ok(found)
    }

    /// Lists the skills the tool can see and compares the list with what the stage allows.
    async fn skills_are_as_allowed(
        &self,
        session: &mut dyn SandboxSession,
        home: &str,
        flag_set: FlagSet,
    ) -> bool {
        let allowed: Vec<String> = match flag_set {
            FlagSet::Standard => Vec::new(),
            FlagSet::Specification => {
                let mut names = self.config.spec_skills.clone().unwrap_or_default();
                names.sort();
                names.dedup();
                names
            }
        };
        let Ok(argv) = self.short_argv(home, argv::skill_listing_args()) else {
            return false;
        };
        match run_probe_command(session, &self.io, argv, ProbeStep::Trial).await {
            Ok(out) if out.exit_code == Some(0) => {
                let visible = events::visible_skills(&out.stdout);
                if visible != allowed {
                    // The names the tool lists can be chosen by the repository, so the log gets
                    // how many there are and a short digest of each set: the digests differ when
                    // the sets differ, and two lines about one set match.
                    tracing::warn!(
                        visible_count = visible.len(),
                        allowed_count = allowed.len(),
                        visible_sha256 = crate::digest::names(&visible),
                        allowed_sha256 = crate::digest::names(&allowed),
                        "the skills the tool can see are not the stage's skills"
                    );
                }
                visible == allowed
            }
            _ => false,
        }
    }

    async fn run_inner(
        &self,
        session: &mut dyn SandboxSession,
        req: AgentRunRequest,
        cancel: &dyn CancelSignal,
    ) -> AgentRunReport {
        if cancel.is_cancelled() {
            return early(AgentRunError::Cancelled, None);
        }
        let target = match VerifiedTarget::check(session.posture()) {
            Ok(target) => target,
            Err(refusal) => {
                tracing::warn!(%refusal, "the sandbox is not a verified target; the tool was not started");
                return early(never_started(), None);
            }
        };
        let caps = match self.capabilities_for(session).await {
            Ok(caps) => caps,
            Err(ProbeError::UnsupportedVersion { found }) => {
                tracing::warn!(%found, "the Codex version is not accepted; the stage is blocked");
                return early(
                    AgentRunError::CapabilityMissing(Capability::HeadlessMultiTurn),
                    None,
                );
            }
            Err(error) => {
                tracing::warn!(?error, "the Codex probe failed");
                return early(never_started(), None);
            }
        };
        let version = Some(caps.runtime_version.clone());
        if let Some(missing) = missing_capability(&caps, req.flag_set) {
            return early(AgentRunError::CapabilityMissing(missing), version);
        }
        if req.flag_set == FlagSet::Specification && self.config.spec_skills.is_none() {
            return early(
                AgentRunError::CapabilityMissing(Capability::SkillInvocation),
                version,
            );
        }
        self.runs.fetch_add(1, Ordering::SeqCst);

        let home = self.homes.next(req.attempt);
        if let Err(error) =
            crate::report::exec_prep(session, make_home_argv(&home), None, cancel).await
        {
            return early(error, version);
        }
        if !self
            .skills_are_as_allowed(session, &home, req.flag_set)
            .await
        {
            return early(never_started(), version);
        }

        let Ok(base) = broker_origin(req.broker.base_url.as_str()) else {
            tracing::warn!("the broker address cannot be given to the tool");
            return early(never_started(), version);
        };
        let plan = argv::Plan {
            model: req.model.model.as_str(),
            broker_origin: &base,
            shell: argv::grants_shell(&req.tools),
            retries: self.config.retries,
        };
        let args = match argv::build(&plan, &target) {
            Ok(args) => args,
            Err(refusal) => {
                tracing::warn!(%refusal, "the Codex arguments were refused");
                return early(never_started(), version);
            }
        };
        let env = ToolEnv::new()
            .set(EnvName::Home, home)
            .and_then(|e| e.set(EnvName::Path, self.config.path.clone()));
        let Ok(env) = env else {
            return early(never_started(), version);
        };
        let soft = u32::try_from(req.limits.max_wall_time_seconds.get())
            .unwrap_or(u32::MAX)
            .max(1);
        let command = ToolCommand {
            env,
            soft_deadline_seconds: soft,
            program: self.config.binary.clone(),
            args,
        };
        let hard = Duration::from_secs(u64::from(soft) + u64::from(HARD_DEADLINE_MARGIN_SECONDS));
        let cap = self
            .config
            .transcript_cap_bytes
            .max(capture_floor(req.max_output_bytes));
        let ended = exec_tool(
            session,
            &self.io,
            command.into_argv(),
            prompt::render(&req.prompt).into_bytes(),
            hard,
            cap,
            cancel,
        )
        .await;
        let end = match ended {
            ExecEnd::Failed(error) => RunEnd::failed(error, "the sandbox ended the command"),
            ExecEnd::Finished {
                result,
                stdout,
                stderr,
            } => interpret(&result, stdout, stderr, cancel.is_cancelled(), &req),
        };
        assemble(&self.io, version, &req, end).await
    }
}

/// The error for a run whose tool never started. The closed set has no variant for a refused
/// sandbox, refused arguments or skills that are not the stage's, so the report says the process
/// failed with no exit.
fn never_started() -> AgentRunError {
    AgentRunError::ProcessFailed(ExitInfo {
        code: None,
        signal: None,
    })
}

fn missing_capability(caps: &RuntimeCapabilities, flag_set: FlagSet) -> Option<Capability> {
    let mut needed = vec![
        Capability::StructuredStream,
        Capability::HeadlessMultiTurn,
        Capability::BaseUrlOverride,
        Capability::CredentialFromFile,
    ];
    if flag_set == FlagSet::Specification {
        needed.insert(0, Capability::SkillInvocation);
    }
    needed.into_iter().find(|c| !caps.supports(*c))
}

/// The observations of a probe, from `exec --help` and `features list`.
fn observations(help: &str, features: &str, version: &str) -> Vec<CapabilityObservation> {
    let verified = format!("verified by the agent runtime spike for version {version}");
    let help_has = |flag: &str| has_flag(help, flag);
    let known: Vec<&str> = features
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    let missing: Vec<&str> = argv::Feature::all_names()
        .into_iter()
        .filter(|name| !known.contains(name))
        .collect();
    let features_ok = missing.is_empty();
    let features_source = if features_ok {
        "codex features list: every feature the adapter switches off exists".to_owned()
    } else {
        format!("codex features list: missing {}", missing.join(", "))
    };
    vec![
        observation(
            Capability::StructuredStream,
            help_has("--json"),
            "codex exec --help: --json",
        ),
        observation(
            Capability::HeadlessMultiTurn,
            help_has("--ephemeral") && help_has("--disable") && features_ok,
            features_source,
        ),
        observation(
            Capability::BudgetFlag,
            false,
            "codex has no turn or budget flag (spike 4.7); the broker counts requests",
        ),
        observation(
            Capability::SkillInvocation,
            help_has("--config") && help_has("--disable"),
            "codex exec --help: --config and --disable; the stage's skills are checked before each run with debug prompt-input",
        ),
        observation(
            Capability::BaseUrlOverride,
            help_has("--config"),
            format!("codex exec --help: --config; a custom provider entry {verified}"),
        ),
        observation(
            Capability::CredentialFromFile,
            help_has("--config"),
            format!("codex exec --help: --config; the provider auth command {verified}"),
        ),
        observation(
            Capability::PermissionDenialReport,
            false,
            "codex reports no permission denials (spike 4.7)",
        ),
        observation(
            Capability::JsonSchemaOutput,
            false,
            "codex --output-schema is not used with the factory schemas; the engine validates the bytes",
        ),
    ]
}

fn interpret(
    result: &ExecResult,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    cancel_set: bool,
    req: &AgentRunRequest,
) -> RunEnd {
    let stream = events::parse(&stdout);
    // One `factory.tool_call` span for each call in the stream: a fixed name, a digest of the
    // arguments and the outcome, and none of the text the tool printed.
    crate::toolspan::emit(req, &stream.tool_calls);
    let exit = exit_info(result);
    let requests = if stream.turn_started {
        stream.tool_items + stream.reconnects + 1
    } else {
        0
    };
    let usage = usage_of(stream.input_tokens, stream.output_tokens, 0, requests);
    let denials = stream
        .denials
        .iter()
        .map(|d| Denial {
            tool: d.tool.clone(),
            reason: d.reason.chars().take(300).collect(),
        })
        .collect();
    let outcome = classify(result, &stream, exit, cancel_set);
    RunEnd {
        outcome,
        usage,
        denials,
        exit: Some(exit),
        stdout,
        stderr,
        note: crate::report::NOTE_FINISHED.to_owned(),
    }
}

/// Success is a `turn.completed` event, no `turn.failed` and exit code 0.
fn classify(
    result: &ExecResult,
    stream: &events::Stream,
    exit: ExitInfo,
    cancel_set: bool,
) -> Result<Vec<u8>, AgentRunError> {
    if result.timed_out || soft_deadline_passed(result) {
        return Err(AgentRunError::Timeout);
    }
    if result.oom_killed {
        return Err(AgentRunError::ProcessFailed(exit));
    }
    if let Some(message) = stream
        .failed
        .as_ref()
        .or(stream.last_error.as_ref().filter(|_| !stream.completed))
    {
        return Err(classify_message(message, exit));
    }
    if stream.completed && exit.code == Some(0) {
        return stream
            .final_message
            .clone()
            .map(String::into_bytes)
            .ok_or(AgentRunError::OutputMissing);
    }
    Err(if result.stdout_truncated {
        AgentRunError::OutputTooLarge
    } else if cancel_set || result.signal.is_some() || exit.code == Some(143) {
        AgentRunError::Cancelled
    } else if exit.code == Some(0) {
        AgentRunError::OutputMissing
    } else {
        AgentRunError::ProcessFailed(exit)
    })
}

/// True when `text` holds `code` as a whole number, such as `status 401`, and not `10401`.
fn has_status(text: &str, code: &str) -> bool {
    text.match_indices(code).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + code.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_digit()) && !after.is_some_and(|c| c.is_ascii_digit())
    })
}

/// Maps the words of an error event to the closed set. Codex puts the HTTP status in the text.
fn classify_message(message: &str, exit: ExitInfo) -> AgentRunError {
    let lower = message.to_ascii_lowercase();
    let status = |codes: &[&str]| codes.iter().any(|c| has_status(&lower, c));
    if status(&["401", "403"])
        || lower.contains("unauthorized")
        || lower.contains("missing environment variable")
        || lower.contains("incorrect api key")
        || lower.contains("invalid api key")
    {
        AgentRunError::AuthenticationRequired
    } else if status(&["402"])
        || lower.contains("payment required")
        || lower.contains("insufficient_quota")
    {
        AgentRunError::BudgetRefused
    } else if status(&["429"])
        || lower.contains("too many requests")
        || lower.contains("rate limit")
    {
        AgentRunError::RateLimited { retry_after: None }
    } else if status(&["500", "502", "503", "504", "529"])
        || lower.contains("high demand")
        || lower.contains("overloaded")
        || lower.contains("connection failed")
        || lower.contains("error sending request")
        || lower.contains("stream disconnected")
    {
        AgentRunError::ProviderUnavailable
    } else {
        AgentRunError::ProcessFailed(exit)
    }
}

impl AgentRuntime for CodexRuntime {
    fn id(&self) -> &RuntimeId {
        &self.id
    }

    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn probe<'life0, 'life1, 'async_trait>(
        &'life0 self,
        session: &'life1 mut dyn SandboxSession,
    ) -> BoxFuture<'async_trait, Result<RuntimeCapabilities, ProbeError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let found = self.probe_inner(session).await?;
            self.cache
                .remember(&session.posture().image.clone(), &found);
            Ok(found)
        })
    }

    fn run<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        session: &'life1 mut dyn SandboxSession,
        req: AgentRunRequest,
        cancel: &'life2 dyn CancelSignal,
    ) -> BoxFuture<'async_trait, AgentRunReport>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.run_inner(session, req, cancel).await })
    }
}
