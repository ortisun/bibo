//! The scripted adversarial runtime (FX-ADV): an `AgentRuntime` that does exactly what its script
//! says and records every prompt it is given.
//!
//! The negative tests of the factory assume the model is fully controlled by an attacker
//! (negative test catalog, principle 1). FX-ADV is that attacker, with no model behind it. A test
//! queues a script: tool calls to run inside the sandbox, claims to make (such as "every gate
//! passed"), the final output, the usage to report and how the run ends. The runtime plays the
//! script back without judgment, runs each tool call through the sandbox session it is given, and
//! stores a transcript of what happened. It never marks anything successful: its outcome is a
//! report, as the port requires.
//!
//! Every prompt is recorded with its two parts apart: the factory's instructions and the data
//! envelope, each data part with its source, class and hash. A test reads them back with
//! [`FakeAgentRuntime::recorded_prompts`] to prove, for example, that untrusted text never reached
//! the instructions.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::agent_manifest::AllowedTool;
use factory_domain::values::MediaType;
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{
    AgentRef, AgentRunError, AgentRunReport, AgentRunRequest, AgentRuntime, AssembledPrompt,
    Capability, CapabilityObservation, DataPart, Denial, ExitInfo, FlagSet, ModelSelection,
    ProbeError, ProbeStep, RawOutput, RuntimeCapabilities, RuntimeId, Usage,
};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{ExecArgv, ExecRequest, ProvisionStage, SandboxError, SandboxSession};

use crate::contracts::agent::{AgentRuntimeSubject, Behavior};

/// The version string the fake reports.
pub const FAKE_RUNTIME_VERSION: &str = "fake-1.0.0";

/// A deliberate fault, for proving that the contract suite can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeDefect {
    /// A cancel signal is never looked at.
    IgnoresCancellation,
    /// Tool calls the script says were denied are left out of the outcome.
    SwallowsDenials,
    /// The output is judged: anything but a JSON object is turned into `OutputMissing`.
    JudgesOutput,
    /// The cost limit of the request is never checked.
    IgnoresBudget,
    /// Every failure is reported as `ProcessFailed`.
    BlursFailures,
    /// The transcript reference points at nothing.
    LosesTranscript,
    /// The probe reports every capability as present.
    GuessesCapabilities,
    /// A failed run reports no usage and no transcript.
    DropsPartialUsage,
    /// A run reports no usage even when it finished.
    ForgetsUsage,
    /// An output over `max_output_bytes` is returned whole.
    IgnoresOutputLimit,
    /// The second probe of a runtime reports another version.
    FlakyProbe,
}

/// Each defect and the checks of `contracts::agent` that must fail when the fake has it.
pub const DEFECTS: &[(RuntimeDefect, &[&str])] = &[
    (
        RuntimeDefect::IgnoresCancellation,
        &[
            "a_cancel_that_is_already_set_stops_the_run",
            "a_cancel_during_a_run_stops_it_promptly",
        ],
    ),
    (
        RuntimeDefect::SwallowsDenials,
        &["denied_tool_calls_are_reported"],
    ),
    (
        RuntimeDefect::JudgesOutput,
        &["a_run_returns_the_output_unjudged_with_a_stored_transcript"],
    ),
    (
        RuntimeDefect::IgnoresBudget,
        &["a_run_over_its_cost_limit_is_refused"],
    ),
    (
        RuntimeDefect::BlursFailures,
        &["every_failure_keeps_its_own_closed_variant"],
    ),
    (
        RuntimeDefect::LosesTranscript,
        &["a_run_returns_the_output_unjudged_with_a_stored_transcript"],
    ),
    (
        RuntimeDefect::GuessesCapabilities,
        &["a_run_that_needs_a_missing_capability_is_refused"],
    ),
    (
        RuntimeDefect::DropsPartialUsage,
        &["a_failed_run_still_reports_usage_and_transcript"],
    ),
    (RuntimeDefect::ForgetsUsage, &["a_run_reports_what_it_used"]),
    (
        RuntimeDefect::IgnoresOutputLimit,
        &["output_is_bytes_and_a_oversize_output_is_a_failure"],
    ),
    (
        RuntimeDefect::FlakyProbe,
        &["probing_reports_a_version_and_its_observations_and_repeats"],
    ),
];

/// One thing the scripted attacker does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptedAction {
    /// Runs this command inside the sandbox session, as the agent's shell tool would.
    Exec(Vec<String>),
    /// Says something about the work, such as "all gates passed". It has no effect.
    Claim(String),
}

/// How a scripted run ends.
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptEnd {
    /// Returns the script's output.
    Finish,
    /// Fails with this error.
    Fail(AgentRunError),
    /// Keeps going until the cancel signal is set.
    UntilCancelled,
}

/// What the scripted attacker does during one call to `run`.
#[derive(Debug, Clone, PartialEq)]
pub struct AdversarialScript {
    /// The actions, in order.
    pub actions: Vec<ScriptedAction>,
    /// The final output, unvalidated. It may be anything.
    pub output: serde_json::Value,
    /// The usage to report.
    pub usage: Usage,
    /// Tool calls to report as denied.
    pub denials: Vec<Denial>,
    /// How the run ends.
    pub end: ScriptEnd,
}

impl AdversarialScript {
    /// A script that does nothing and returns this output.
    #[must_use]
    pub fn returning(output: serde_json::Value) -> Self {
        Self {
            actions: Vec::new(),
            output,
            usage: Usage::default(),
            denials: Vec::new(),
            end: ScriptEnd::Finish,
        }
    }

    /// Adds a command to run in the sandbox.
    #[must_use]
    pub fn then_exec(mut self, words: &[&str]) -> Self {
        self.actions.push(ScriptedAction::Exec(
            words.iter().map(|word| (*word).to_owned()).collect(),
        ));
        self
    }

    /// Adds a claim to make.
    #[must_use]
    pub fn then_claim(mut self, claim: &str) -> Self {
        self.actions.push(ScriptedAction::Claim(claim.to_owned()));
        self
    }

    /// Ends the run with this error instead of an output.
    #[must_use]
    pub fn failing_with(mut self, error: AgentRunError) -> Self {
        self.end = ScriptEnd::Fail(error);
        self
    }
}

/// A prompt as the runtime received it, with its two parts apart.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordedPrompt {
    /// The agent the run was for.
    pub agent: AgentRef,
    /// The factory's own instructions.
    pub instructions: String,
    /// The data envelope, one entry per untrusted part, in order.
    pub data: Vec<DataPart>,
    /// The tools policy granted for the run.
    pub granted_tools: Vec<AllowedTool>,
    /// The flag set of the stage.
    pub flag_set: FlagSet,
    /// The model and runtime the run was asked to use.
    pub model: ModelSelection,
}

/// What a scripted run did with the sandbox, in order. A test reads it to see what the attacker
/// actually managed to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Performed {
    /// A command ran and ended with this exit code.
    Exec {
        /// The command.
        argv: Vec<String>,
        /// Its exit code.
        exit_code: Option<i32>,
    },
    /// A command was refused or failed in the sandbox.
    ExecFailed {
        /// The command.
        argv: Vec<String>,
        /// What the sandbox said.
        error: SandboxError,
    },
    /// The attacker made a claim.
    Claimed(String),
}

#[derive(Default)]
struct State {
    scripts: VecDeque<AdversarialScript>,
    prompts: Vec<RecordedPrompt>,
    performed: Vec<Performed>,
    missing: Vec<Capability>,
    probes: u32,
}

/// The scripted adversarial runtime. Reports fidelity `fake`.
#[derive(Clone)]
pub struct FakeAgentRuntime {
    id: RuntimeId,
    artifacts: Arc<dyn ArtifactStore>,
    state: Arc<Mutex<State>>,
    defect: Option<RuntimeDefect>,
}

const ALL_CAPABILITIES: [Capability; 8] = [
    Capability::JsonSchemaOutput,
    Capability::StructuredStream,
    Capability::BudgetFlag,
    Capability::SkillInvocation,
    Capability::HeadlessMultiTurn,
    Capability::BaseUrlOverride,
    Capability::CredentialFromFile,
    Capability::PermissionDenialReport,
];

impl FakeAgentRuntime {
    /// A runtime that stores transcripts in `artifacts`.
    ///
    /// # Panics
    /// Never in practice: the runtime name is a valid slug.
    #[must_use]
    pub fn new(artifacts: Arc<dyn ArtifactStore>) -> Self {
        Self::build(artifacts, None)
    }

    /// A runtime that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(artifacts: Arc<dyn ArtifactStore>, defect: RuntimeDefect) -> Self {
        Self::build(artifacts, Some(defect))
    }

    fn build(artifacts: Arc<dyn ArtifactStore>, defect: Option<RuntimeDefect>) -> Self {
        Self {
            id: RuntimeId::new("fake").expect("fake is a valid runtime id"),
            artifacts,
            state: Arc::new(Mutex::new(State::default())),
            defect,
        }
    }

    /// Queues a script for a later call to `run`. Scripts are played in the order they were
    /// queued, one per call.
    pub fn queue(&self, script: AdversarialScript) {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .scripts
            .push_back(script);
    }

    /// Every prompt the runtime received, oldest first.
    #[must_use]
    pub fn recorded_prompts(&self) -> Vec<RecordedPrompt> {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .prompts
            .clone()
    }

    /// Everything the scripted attacker did, oldest first.
    #[must_use]
    pub fn performed(&self) -> Vec<Performed> {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .performed
            .clone()
    }

    /// Makes later probes report this capability as missing.
    pub fn remove_capability(&self, capability: Capability) {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .missing
            .push(capability);
    }

    fn has(&self, defect: RuntimeDefect) -> bool {
        self.defect == Some(defect)
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        let (missing, probes) = {
            let state = self.state.lock().expect("the lock is never poisoned");
            (state.missing.clone(), state.probes)
        };
        let flaky = self.has(RuntimeDefect::FlakyProbe) && probes > 0;
        RuntimeCapabilities {
            runtime_version: if flaky {
                format!("{FAKE_RUNTIME_VERSION}-{probes}")
            } else {
                FAKE_RUNTIME_VERSION.to_owned()
            },
            observations: ALL_CAPABILITIES
                .iter()
                .map(|capability| CapabilityObservation {
                    capability: *capability,
                    supported: self.has(RuntimeDefect::GuessesCapabilities)
                        || !missing.contains(capability),
                    source: "the scripted fake's capability list".to_owned(),
                })
                .collect(),
        }
    }

    fn record(&self, prompt_source: &AgentRunRequest) {
        let AssembledPrompt { instructions, data } = prompt_source.prompt.clone();
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .prompts
            .push(RecordedPrompt {
                agent: prompt_source.agent.clone(),
                instructions,
                data,
                granted_tools: prompt_source.tools.clone(),
                flag_set: prompt_source.flag_set,
                model: prompt_source.model.clone(),
            });
    }

    fn note(&self, performed: Performed) {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .performed
            .push(performed);
    }
}

fn exec_request(words: &[String]) -> Result<ExecRequest, SandboxError> {
    Ok(ExecRequest {
        argv: ExecArgv::new(words.to_vec())
            .map_err(|_| SandboxError::ProvisionFailed(ProvisionStage::Create))?,
        cwd: None,
        stdin: None,
        timeout: Duration::from_secs(30),
        max_output_bytes: 64 * 1024,
    })
}

/// The event Claude Code writes for a typed command when it replays the prompt
/// (`--input-format=stream-json --replay-user-messages`, read from version 2.1.325). The scripted
/// runtime writes it for a specification run whose prompt starts with a command, so a stage that
/// checks what reached the arguments of a skill finds the invocation as it would in a real
/// transcript.
fn replayed_command(instructions: &str) -> Option<serde_json::Value> {
    let rest = instructions.strip_prefix(['/', '$'])?;
    let (name, arguments) = rest.split_once(' ').unwrap_or((rest, ""));
    if name.is_empty() {
        return None;
    }
    let sigil = &instructions[..1];
    Some(serde_json::json!({
        "type": "user",
        "isReplay": true,
        "message": {
            "role": "user",
            "content": format!(
                "<command-message>{name}</command-message>\n<command-name>{sigil}{name}</command-name>\n<command-args>{arguments}</command-args>"
            ),
        },
    }))
}

#[async_trait]
impl AgentRuntime for FakeAgentRuntime {
    fn id(&self) -> &RuntimeId {
        &self.id
    }

    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn probe(
        &self,
        _session: &mut dyn SandboxSession,
    ) -> Result<RuntimeCapabilities, ProbeError> {
        let capabilities = self.capabilities();
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .probes += 1;
        let _ = ProbeStep::Version;
        Ok(capabilities)
    }

    async fn run(
        &self,
        session: &mut dyn SandboxSession,
        req: AgentRunRequest,
        cancel: &dyn CancelSignal,
    ) -> AgentRunReport {
        self.record(&req);
        let mut report = AgentRunReport {
            outcome: Err(AgentRunError::OutputMissing),
            transcript: None,
            usage: Usage::default(),
            runtime_version: None,
            exit: None,
            permission_denials: Vec::new(),
        };
        let honours_cancel = !self.has(RuntimeDefect::IgnoresCancellation);
        if honours_cancel && cancel.is_cancelled() {
            report.outcome = Err(AgentRunError::Cancelled);
            return report;
        }
        if req.flag_set == FlagSet::Specification
            && !self.capabilities().supports(Capability::SkillInvocation)
        {
            report.outcome = Err(AgentRunError::CapabilityMissing(
                Capability::SkillInvocation,
            ));
            return report;
        }
        let Some(script) = self
            .state
            .lock()
            .expect("the lock is never poisoned")
            .scripts
            .pop_front()
        else {
            return report;
        };
        report.runtime_version = Some(FAKE_RUNTIME_VERSION.to_owned());

        let limit_micro = (req.limits.max_cost_usd.as_f64() * 1_000_000.0).ceil();
        if !self.has(RuntimeDefect::IgnoresBudget) && (script.usage.cost.0 as f64) > limit_micro {
            report.usage = script.usage;
            report.outcome = Err(AgentRunError::BudgetRefused);
            return report;
        }

        let mut transcript = Vec::new();
        if req.flag_set == FlagSet::Specification
            && let Some(replay) = replayed_command(&req.prompt.instructions)
        {
            transcript.push(replay);
        }
        let mut cancelled = false;
        for action in &script.actions {
            if honours_cancel && cancel.is_cancelled() {
                cancelled = true;
                break;
            }
            match action {
                ScriptedAction::Claim(text) => {
                    self.note(Performed::Claimed(text.clone()));
                    transcript.push(serde_json::json!({ "type": "claim", "text": text }));
                }
                ScriptedAction::Exec(words) => {
                    let outcome = match exec_request(words) {
                        Ok(exec) => session.exec(exec, cancel).await,
                        Err(error) => Err(error),
                    };
                    match outcome {
                        Ok(result) => {
                            self.note(Performed::Exec {
                                argv: words.clone(),
                                exit_code: result.exit_code,
                            });
                            transcript.push(serde_json::json!({
                                "type": "exec",
                                "argv": words,
                                "exit_code": result.exit_code,
                                "stdout_sha256": result.stdout.sha256.to_string(),
                            }));
                        }
                        Err(SandboxError::Cancelled) => {
                            cancelled = true;
                            break;
                        }
                        Err(error) => {
                            self.note(Performed::ExecFailed {
                                argv: words.clone(),
                                error,
                            });
                            transcript
                                .push(serde_json::json!({ "type": "exec_failed", "argv": words }));
                        }
                    }
                }
            }
        }

        // The usage, denials and transcript are reported whether the run worked or not.
        let report_partial = !self.has(RuntimeDefect::DropsPartialUsage);
        let denials = if self.has(RuntimeDefect::SwallowsDenials) {
            Vec::new()
        } else {
            script.denials.clone()
        };
        let usage = if self.has(RuntimeDefect::ForgetsUsage) {
            Usage::default()
        } else {
            script.usage
        };
        let store_transcript = |bytes: Vec<u8>| async move {
            let media = MediaType::parse("application/json").expect("a valid media type");
            self.artifacts.put(bytes, media).await.ok()
        };
        let transcript_bytes = serde_json::to_vec(&transcript).unwrap_or_default();

        let mut failure: Option<AgentRunError> = None;
        if cancelled {
            failure = Some(AgentRunError::Cancelled);
        } else {
            match &script.end {
                ScriptEnd::UntilCancelled => {
                    if honours_cancel {
                        cancel.cancelled().await;
                        report.outcome = Err(AgentRunError::Cancelled);
                        return report;
                    }
                    // A runtime that ignores the cancel has nothing to wait for and never returns.
                    std::future::pending::<()>().await;
                }
                ScriptEnd::Fail(error) => {
                    failure = Some(if self.has(RuntimeDefect::BlursFailures) {
                        AgentRunError::ProcessFailed(ExitInfo {
                            code: Some(1),
                            signal: None,
                        })
                    } else {
                        error.clone()
                    });
                }
                ScriptEnd::Finish => {}
            }
        }

        let output_bytes = serde_json::to_vec(&script.output).unwrap_or_default();
        if failure.is_none() {
            if self.has(RuntimeDefect::JudgesOutput) && !script.output.is_object() {
                failure = Some(AgentRunError::OutputMissing);
            } else if output_bytes.len() as u64 > req.max_output_bytes
                && !self.has(RuntimeDefect::IgnoresOutputLimit)
            {
                failure = Some(AgentRunError::OutputTooLarge);
            }
        }

        let is_failure = failure.is_some();
        if !is_failure || report_partial {
            report.usage = usage;
            report.permission_denials = denials;
            report.transcript = if self.has(RuntimeDefect::LosesTranscript) && !is_failure {
                // A reference to bytes that were never stored.
                match store_transcript(b"lost".to_vec()).await {
                    Some(mut lost) => {
                        lost.sha256 = factory_domain::values::Sha256Digest::of(&transcript_bytes);
                        Some(lost)
                    }
                    None => None,
                }
            } else {
                store_transcript(transcript_bytes).await
            };
            report.exit = Some(ExitInfo {
                code: Some(if is_failure { 1 } else { 0 }),
                signal: None,
            });
        }
        report.outcome = match failure {
            Some(error) => Err(error),
            None => Ok(RawOutput::new(output_bytes)),
        };
        report
    }
}

/// The scripted runtime packaged as a subject of the agent runtime contract suite.
pub struct FakeAgentRuntimeSubject {
    clock: Arc<crate::clock::FakeClock>,
    artifacts: Arc<crate::artifact::InMemoryArtifactStore>,
    sandbox: crate::sandbox::FakeSandbox,
    runtime: FakeAgentRuntime,
    ids: crate::fixtures::Ids,
}

impl FakeAgentRuntimeSubject {
    /// A faithful fake.
    #[must_use]
    pub fn new() -> Self {
        Self::build(None)
    }

    /// A fake that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(defect: RuntimeDefect) -> Self {
        Self::build(Some(defect))
    }

    fn build(defect: Option<RuntimeDefect>) -> Self {
        let clock = Arc::new(crate::clock::FakeClock::new());
        let artifacts = Arc::new(crate::artifact::InMemoryArtifactStore::new());
        let sandbox = crate::sandbox::FakeSandbox::new(
            Arc::clone(&clock),
            artifacts.clone(),
            crate::fixtures::sandbox_policy(),
        );
        let runtime = match defect {
            Some(defect) => FakeAgentRuntime::with_defect(artifacts.clone(), defect),
            None => FakeAgentRuntime::new(artifacts.clone()),
        };
        Self {
            clock,
            artifacts,
            sandbox,
            runtime,
            ids: crate::fixtures::Ids::new(),
        }
    }

    /// The runtime, to read what it recorded.
    #[must_use]
    pub fn fake(&self) -> &FakeAgentRuntime {
        &self.runtime
    }

    /// The stored bytes of a transcript, read as the test tenant after the engine indexed it.
    pub async fn transcript_bytes(
        &self,
        reference: &factory_domain::contracts::ArtifactRef,
    ) -> Option<Vec<u8>> {
        let scope = factory_domain::scope::TenantScope::new(
            factory_domain::ids::TenantId::parse("00000000-0000-7000-8000-00000000000a")
                .expect("a tenant id"),
        );
        self.artifacts.grant(scope.tenant_id(), &reference.sha256);
        self.artifacts.get(&scope, reference).await.ok()
    }

    /// The clock the sandbox uses.
    #[must_use]
    pub fn clock(&self) -> &crate::clock::FakeClock {
        &self.clock
    }
}

impl Default for FakeAgentRuntimeSubject {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AgentRuntimeSubject for FakeAgentRuntimeSubject {
    fn runtime(&self) -> &dyn AgentRuntime {
        &self.runtime
    }

    async fn transcript_is_stored(
        &self,
        reference: &factory_domain::contracts::ArtifactRef,
    ) -> Result<bool, String> {
        let scope = factory_domain::scope::TenantScope::new(
            factory_domain::ids::TenantId::parse("00000000-0000-7000-8000-00000000000a")
                .expect("a tenant id"),
        );
        self.artifacts.grant(scope.tenant_id(), &reference.sha256);
        self.artifacts
            .exists(&scope, reference)
            .await
            .map_err(|error| format!("look for the transcript: {error:?}"))
    }

    async fn session(&self) -> Result<Box<dyn SandboxSession>, String> {
        let spec =
            crate::fixtures::sandbox_spec(&self.ids, factory_ports::sandbox::SandboxProfile::Agent);
        factory_ports::sandbox::SandboxProvider::create_verified(
            &self.sandbox,
            spec,
            &crate::clock::FakeCancel::new(),
        )
        .await
        .map_err(|error| format!("create the agent sandbox: {error:?}"))
    }

    fn request(&self) -> AgentRunRequest {
        crate::fixtures::agent_run_request(&self.ids)
    }

    async fn arrange(&self, behavior: Behavior) -> bool {
        let script = match behavior {
            Behavior::Finish { output, usage } => AdversarialScript {
                usage,
                ..AdversarialScript::returning(output)
            },
            Behavior::FinishWithDenials(denials) => AdversarialScript {
                denials,
                ..AdversarialScript::returning(serde_json::json!({}))
            },
            Behavior::Fail { error, usage } => AdversarialScript {
                usage,
                ..AdversarialScript::returning(serde_json::Value::Null).failing_with(error)
            },
            Behavior::RunUntilCancelled => AdversarialScript {
                end: ScriptEnd::UntilCancelled,
                ..AdversarialScript::returning(serde_json::Value::Null)
            },
        };
        self.runtime.queue(script);
        true
    }

    async fn remove_capability(&self, capability: Capability) -> bool {
        self.runtime.remove_capability(capability);
        true
    }
}
