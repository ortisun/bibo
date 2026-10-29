//! The Claude Code adapter (`claude-code-cli`).
//!
//! Claude Code runs inside the `agent` sandbox, headless, with the prompt on standard input. The
//! adapter builds the command (`argv`), starts it through the sandbox session, reads the
//! `stream-json` event stream (`events`) and reports what happened. It never marks a stage
//! successful: the outcome is the final text as bytes, which the engine validates.
//!
//! What the adapter does to keep the container as the only boundary (spike sections 4.3 to 4.8):
//!
//! * **Credential.** A `--settings` document names an `apiKeyHelper` that prints the job token
//!   file. The token is in no variable, no argument and no log.
//! * **Traffic.** `ANTHROPIC_BASE_URL` is the broker. `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`
//!   stops telemetry and the update check. Retries are capped at `CLAUDE_CODE_MAX_RETRIES`.
//! * **Repository configuration.** `--setting-sources=user` and `--strict-mcp-config` leave the
//!   repository's `.claude/settings.json`, `.mcp.json` and `CLAUDE.md` unread, and the user home is
//!   a new directory for every run, so a hook, an `env` block or a server in the repository, or
//!   left behind by an earlier run, never runs.
//! * **Skills.** Standard stages run with `--disable-slash-commands`. The specification stage runs
//!   without it and gets exactly the pinned skills, written into the run's home.
//! * **Failures.** `is_error` and `terminal_reason` decide, never `subtype` and never the exit code.

pub mod argv;
pub mod events;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{
    AgentRunError, AgentRunReport, AgentRunRequest, AgentRuntime, Capability, Denial, ExitInfo,
    FlagSet, ProbeError, ProbeStep, RuntimeCapabilities, RuntimeId,
};
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::SandboxSession;

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
    ExecEnd, RunEnd, assemble, capture_floor, early, exec_prep, exec_tool, exit_info,
    soft_deadline_passed, usage_of,
};
use crate::skills::SkillBundle;
use crate::target::VerifiedTarget;

/// The runtime's name in manifests and routing (`recommended_models[].runtime_id`).
pub const RUNTIME_NAME: &str = "claude-code-cli";

/// The version the spike tested.
pub const PINNED_VERSION: &str = "2.1.311";

/// Where the image puts the tool.
pub const DEFAULT_BINARY: &str = "/usr/local/bin/claude";

/// How the adapter is set up. The defaults match the pinned image.
#[derive(Debug, Clone)]
pub struct ClaudeCodeConfig {
    /// The path of the tool inside the image.
    pub binary: String,
    /// The versions a stage may run on. Anything else is BLOCKED.
    pub accepted_versions: Vec<String>,
    /// The `PATH` the tool starts with.
    pub path: String,
    /// The directory under which every run's home is made. The scratch tmpfs.
    pub home_root: String,
    /// How many times the tool retries a failed request (`CLAUDE_CODE_MAX_RETRIES`).
    pub max_retries: u32,
    /// How many bytes of standard output are kept at most. The stream is the transcript.
    pub transcript_cap_bytes: u64,
    /// The most turns the tool may take, whatever the limits ask for.
    pub max_turns_cap: u32,
    /// The skills the specification stage may see. `None` makes that stage unavailable.
    pub spec_skills: Option<SkillBundle>,
}

impl Default for ClaudeCodeConfig {
    fn default() -> Self {
        Self {
            binary: DEFAULT_BINARY.to_owned(),
            accepted_versions: vec![PINNED_VERSION.to_owned()],
            path: "/usr/local/bin:/usr/bin:/bin".to_owned(),
            home_root: "/tmp".to_owned(),
            max_retries: 2,
            transcript_cap_bytes: 16 * 1024 * 1024,
            max_turns_cap: 200,
            spec_skills: None,
        }
    }
}

/// The Claude Code runtime.
pub struct ClaudeCodeRuntime {
    id: RuntimeId,
    config: ClaudeCodeConfig,
    io: RunIo,
    cache: ProbeCache,
    homes: HomeAllocator,
    runs: AtomicU64,
}

impl std::fmt::Debug for ClaudeCodeRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaudeCodeRuntime")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl ClaudeCodeRuntime {
    /// Makes the runtime.
    ///
    /// # Panics
    /// Never in practice: the runtime name is a valid slug.
    #[must_use]
    pub fn new(config: ClaudeCodeConfig, io: RunIo) -> Self {
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

    fn probe_env(&self) -> Result<ToolEnv, ProbeError> {
        ToolEnv::new()
            .set(EnvName::Home, self.config.home_root.clone())
            .and_then(|env| env.set(EnvName::Path, self.config.path.clone()))
            .map_err(|_| ProbeError::ProbeFailed(ProbeStep::Version))
    }

    fn probe_argv(&self, args: &[&str]) -> Result<Vec<String>, ProbeError> {
        Ok(ToolCommand {
            env: self.probe_env()?,
            soft_deadline_seconds: 0,
            program: self.config.binary.clone(),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
        }
        .into_probe_argv())
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
            self.probe_argv(&["--help"])?,
            ProbeStep::Help,
        )
        .await?;
        if help.exit_code != Some(0) {
            return Err(ProbeError::ProbeFailed(ProbeStep::Help));
        }
        // `--max-turns` is hidden: it is not in the help text. The trial gives it an argument that
        // is not a number. A tool that knows the flag says so and stops; a tool that does not
        // says "unknown option". Either way no request is made.
        let trial = run_probe_command(
            session,
            &self.io,
            self.probe_argv(&["-p", "--max-turns=notanumber", "x"])?,
            ProbeStep::Trial,
        )
        .await?;
        let max_turns_known = trial.stderr.contains("must be a number");
        Ok(capabilities(
            version.clone(),
            observations(&help.stdout, max_turns_known, &version),
        ))
    }

    /// The probe result for this session's image: the cached one, or a new probe.
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
                tracing::warn!(%found, "the Claude Code version is not accepted; the stage is blocked");
                return early(
                    AgentRunError::CapabilityMissing(Capability::HeadlessMultiTurn),
                    None,
                );
            }
            Err(error) => {
                tracing::warn!(?error, "the Claude Code probe failed");
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
        if let Err(error) = exec_prep(session, make_home_argv(&home), None, cancel).await {
            return early(error, version);
        }
        if req.flag_set == FlagSet::Specification
            && let Some(bundle) = &self.config.spec_skills
            && let Err(error) = install_skills(session, &home, bundle, cancel).await
        {
            return early(error, version);
        }

        let plan = argv::Plan {
            flag_set: req.flag_set,
            model: req.model.model.as_str(),
            max_turns: u32::try_from(req.limits.max_tool_calls.get())
                .unwrap_or(u32::MAX)
                .saturating_add(1)
                .min(self.config.max_turns_cap),
            max_budget_usd: req.limits.max_cost_usd.as_f64(),
            tools: argv::tools_for(&req.tools, req.flag_set),
        };
        let args = match argv::build(&plan, &target) {
            Ok(args) => args,
            Err(refusal) => {
                tracing::warn!(%refusal, "the Claude Code arguments were refused");
                return early(never_started(), version);
            }
        };
        let Ok(base) = broker_origin(req.broker.base_url.as_str()) else {
            tracing::warn!("the broker address cannot be given to the tool");
            return early(never_started(), version);
        };
        let env = ToolEnv::new()
            .set(EnvName::Home, home)
            .and_then(|e| e.set(EnvName::Path, self.config.path.clone()))
            .and_then(|e| e.set(EnvName::AnthropicBaseUrl, base))
            .and_then(|e| e.set(EnvName::ClaudeDisableNonessentialTraffic, "1"))
            .and_then(|e| {
                e.set(
                    EnvName::ClaudeMaxRetries,
                    self.config.max_retries.to_string(),
                )
            })
            // The tool's own skills are not the factory's to offer; the stage sees the pinned ones.
            .and_then(|e| e.set(EnvName::ClaudeDisableBundledSkills, "1"));
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
/// sandbox or refused arguments, so the report says the process failed with no exit.
fn never_started() -> AgentRunError {
    AgentRunError::ProcessFailed(ExitInfo {
        code: None,
        signal: None,
    })
}

/// The capabilities a run needs, and the first one the probe did not find.
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

/// Writes the pinned skills into the run's home and takes the write bit off the tree.
async fn install_skills(
    session: &mut dyn SandboxSession,
    home: &str,
    bundle: &SkillBundle,
    cancel: &dyn CancelSignal,
) -> Result<(), AgentRunError> {
    exec_prep(
        session,
        vec![
            "/usr/bin/tar".to_owned(),
            "-x".to_owned(),
            "-C".to_owned(),
            home.to_owned(),
            "-f".to_owned(),
            "-".to_owned(),
        ],
        Some(bundle.to_archive()),
        cancel,
    )
    .await?;
    exec_prep(
        session,
        vec![
            "/usr/bin/chmod".to_owned(),
            "-R".to_owned(),
            "a-w".to_owned(),
            format!("{home}/.claude"),
        ],
        None,
        cancel,
    )
    .await
}

/// The observations of a probe, from the help text and the `--max-turns` trial.
fn observations(
    help: &str,
    max_turns_known: bool,
    version: &str,
) -> Vec<factory_ports::agent::CapabilityObservation> {
    let verified = format!("verified by the agent runtime spike for version {version}");
    let help_has = |flag: &str| has_flag(help, flag);
    vec![
        observation(
            Capability::StructuredStream,
            help_has("--output-format") && help.contains("stream-json") && help_has("--verbose"),
            "claude --help: --output-format stream-json and --verbose",
        ),
        observation(
            Capability::HeadlessMultiTurn,
            help_has("--print") && max_turns_known,
            "claude --help: --print; trial: --max-turns is a known option (hidden from help)",
        ),
        observation(
            Capability::BudgetFlag,
            help_has("--max-budget-usd"),
            "claude --help: --max-budget-usd",
        ),
        observation(
            Capability::SkillInvocation,
            help_has("--setting-sources") && help_has("--disable-slash-commands"),
            "claude --help: --setting-sources and --disable-slash-commands; skills reach the user skill root",
        ),
        observation(
            Capability::BaseUrlOverride,
            help_has("--settings"),
            format!("claude --help: --settings; ANTHROPIC_BASE_URL {verified}"),
        ),
        observation(
            Capability::CredentialFromFile,
            help_has("--settings"),
            format!("claude --help: --settings; apiKeyHelper {verified}"),
        ),
        observation(
            Capability::PermissionDenialReport,
            help_has("--output-format"),
            format!("result.permission_denials in the event stream {verified}"),
        ),
        observation(
            Capability::JsonSchemaOutput,
            false,
            "claude --json-schema rejects the factory schemas (spike 4.7); the engine validates the bytes",
        ),
    ]
}

/// What the tool's process and stream say about the run.
fn interpret(
    result: &factory_ports::sandbox::ExecResult,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    cancel_set: bool,
    req: &AgentRunRequest,
) -> RunEnd {
    let stream = events::parse(&stdout);
    // One `factory.tool_call` span for each call in the stream: a fixed name, a digest of the
    // arguments and the outcome, and none of the text the tool printed.
    crate::toolspan::emit(req, &stream.tool_calls());
    let exit = exit_info(result);
    let requests = stream.message_ids.len() as u64 + stream.retries;
    let usage = match &stream.result {
        Some(r) if r.input_tokens > 0 || r.output_tokens > 0 || r.cost_micro > 0 => {
            usage_of(r.input_tokens, r.output_tokens, r.cost_micro, requests)
        }
        _ => usage_of(
            stream.partial_input_tokens,
            stream.partial_output_tokens,
            0,
            requests,
        ),
    };
    let denials = stream
        .result
        .as_ref()
        .map(|r| {
            r.denials
                .iter()
                .map(|d| Denial {
                    tool: d.tool_name.clone(),
                    reason: stream.tool_results.get(&d.tool_use_id).map_or_else(
                        || "the tool refused the call".to_owned(),
                        |text| text.chars().take(300).collect(),
                    ),
                })
                .collect()
        })
        .unwrap_or_default();
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

/// Success is `is_error == false` and `terminal_reason == "completed"` in the one result the tool
/// wrote, and a clean exit: code 0 and no signal. Anything else is a failure with one closed
/// variant.
///
/// The exit status is the part of the outcome that a process inside the sandbox cannot write:
/// the stream is the tool's standard output, and a sibling of the tool can add lines to it
/// (finding SBX-4). A `completed` line followed by a kill, or by an error exit, is therefore not a
/// success (finding RTM-1), and neither is a stream with a second result or with events after
/// the result: the tool writes exactly one result, last. The Codex adapter has the same rule.
/// What these checks do not do is authenticate the lines before the result; the image does that
/// for the tools it installs (their processes cannot be written to through `/proc`), see
/// `infra/sandbox-images/agent/README.md`.
fn classify(
    result: &factory_ports::sandbox::ExecResult,
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
    let Some(done) = &stream.result else {
        return Err(if result.stdout_truncated {
            AgentRunError::OutputTooLarge
        } else if cancel_set || result.signal.is_some() || exit.code == Some(143) {
            AgentRunError::Cancelled
        } else if exit.code == Some(0) {
            AgentRunError::OutputMissing
        } else {
            AgentRunError::ProcessFailed(exit)
        });
    };
    if !done.is_error && done.terminal_reason.as_deref() == Some("completed") {
        let clean_exit = exit.code == Some(0) && result.signal.is_none();
        let one_result_last = stream.result_events == 1 && !stream.events_after_result;
        if clean_exit && one_result_last {
            return Ok(done.text.clone().into_bytes());
        }
        // A result that says `completed`, written by a tool that did not end cleanly or by a
        // stream that was added to.
        return Err(if result.stdout_truncated {
            AgentRunError::OutputTooLarge
        } else if cancel_set || result.signal.is_some() || exit.code == Some(143) {
            AgentRunError::Cancelled
        } else {
            AgentRunError::ProcessFailed(exit)
        });
    }
    Err(classify_error(done, stream, exit))
}

fn classify_error(
    done: &events::ResultEvent,
    stream: &events::Stream,
    exit: ExitInfo,
) -> AgentRunError {
    let reason = done.terminal_reason.as_deref().unwrap_or_default();
    let text = done.text.as_str();
    match (reason, done.subtype.as_str()) {
        ("max_turns" | "budget_exhausted", _) | (_, "error_max_turns" | "error_max_budget_usd") => {
            return AgentRunError::BudgetRefused;
        }
        ("aborted_streaming" | "aborted_tools", _) | (_, "error_during_execution") => {
            return AgentRunError::Cancelled;
        }
        _ => {}
    }
    let status = done.api_error_status.or(stream.last_retry_status);
    match status {
        Some(401 | 403) => return AgentRunError::AuthenticationRequired,
        Some(402) => return AgentRunError::BudgetRefused,
        Some(429) => return AgentRunError::RateLimited { retry_after: None },
        Some(500..=599) => return AgentRunError::ProviderUnavailable,
        _ => {}
    }
    if text.contains("Not logged in") || text.contains("Invalid API key") {
        return AgentRunError::AuthenticationRequired;
    }
    if text.contains("Can't reach the API server") || text.contains("Unable to connect") {
        return AgentRunError::ProviderUnavailable;
    }
    AgentRunError::ProcessFailed(exit)
}

impl AgentRuntime for ClaudeCodeRuntime {
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
