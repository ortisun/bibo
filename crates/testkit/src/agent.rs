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
    AgentRef, AgentRunError, AgentRunOutcome, AgentRunRequest, AgentRuntime, AssembledPrompt,
    Capability, CapabilityObservation, DataPart, Denial, ExitInfo, FlagSet, ModelSelection,
    ProbeError, RuntimeCapabilities, RuntimeId, Usage,
};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{ExecArgv, ExecRequest, SandboxError, SandboxSession};

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
}

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
        let missing = self
            .state
            .lock()
            .expect("the lock is never poisoned")
            .missing
            .clone();
        RuntimeCapabilities {
            runtime_version: FAKE_RUNTIME_VERSION.to_owned(),
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
        argv: ExecArgv::new(words.to_vec()).map_err(|_| {
            SandboxError::ProvisionFailed("the scripted command is empty".to_owned())
        })?,
        cwd: None,
        stdin: None,
        timeout: Duration::from_secs(30),
        max_output_bytes: 64 * 1024,
    })
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
        Ok(self.capabilities())
    }

    async fn run(
        &self,
        session: &mut dyn SandboxSession,
        req: AgentRunRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<AgentRunOutcome, AgentRunError> {
        self.record(&req);
        let honours_cancel = !self.has(RuntimeDefect::IgnoresCancellation);
        if honours_cancel && cancel.is_cancelled() {
            return Err(AgentRunError::Cancelled);
        }
        if req.flag_set == FlagSet::Specification
            && !self.capabilities().supports(Capability::SkillInvocation)
        {
            return Err(AgentRunError::CapabilityMissing(
                Capability::SkillInvocation,
            ));
        }
        let script = self
            .state
            .lock()
            .expect("the lock is never poisoned")
            .scripts
            .pop_front()
            .ok_or(AgentRunError::OutputMissing)?;

        let limit_micro = (req.limits.max_cost_usd.as_f64() * 1_000_000.0).ceil();
        if !self.has(RuntimeDefect::IgnoresBudget) && (script.usage.cost.0 as f64) > limit_micro {
            return Err(AgentRunError::BudgetRefused);
        }

        let mut transcript = Vec::new();
        for action in &script.actions {
            if honours_cancel && cancel.is_cancelled() {
                return Err(AgentRunError::Cancelled);
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
                        Err(SandboxError::Cancelled) => return Err(AgentRunError::Cancelled),
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

        match &script.end {
            ScriptEnd::UntilCancelled => {
                if honours_cancel {
                    cancel.cancelled().await;
                    return Err(AgentRunError::Cancelled);
                }
                // A runtime that ignores the cancel has nothing to wait for and never returns.
                std::future::pending::<()>().await;
            }
            ScriptEnd::Fail(error) => {
                return Err(if self.has(RuntimeDefect::BlursFailures) {
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

        if self.has(RuntimeDefect::JudgesOutput) && !script.output.is_object() {
            return Err(AgentRunError::OutputMissing);
        }
        let transcript_bytes =
            serde_json::to_vec(&transcript).map_err(|_| AgentRunError::OutputMissing)?;
        let media = MediaType::parse("application/json").expect("a valid media type");
        let transcript_ref = if self.has(RuntimeDefect::LosesTranscript) {
            // A reference to bytes that were never stored.
            let mut lost = self
                .artifacts
                .put(b"lost".to_vec(), media.clone())
                .await
                .map_err(|_| AgentRunError::OutputMissing)?;
            lost.sha256 = factory_domain::values::Sha256Digest::of(&transcript_bytes);
            lost
        } else {
            self.artifacts
                .put(transcript_bytes, media)
                .await
                .map_err(|_| AgentRunError::OutputMissing)?
        };
        Ok(AgentRunOutcome {
            output: script.output,
            transcript: transcript_ref,
            usage: script.usage,
            runtime_version: FAKE_RUNTIME_VERSION.to_owned(),
            exit: ExitInfo {
                code: Some(0),
                signal: None,
            },
            permission_denials: if self.has(RuntimeDefect::SwallowsDenials) {
                Vec::new()
            } else {
                script.denials
            },
        })
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

    fn artifacts(&self) -> &dyn ArtifactStore {
        self.artifacts.as_ref()
    }

    async fn session(&self) -> Result<Box<dyn SandboxSession>, String> {
        let spec =
            crate::fixtures::sandbox_spec(&self.ids, factory_ports::sandbox::SandboxProfile::Agent);
        factory_ports::sandbox::SandboxProvider::create_verified(&self.sandbox, spec)
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
            Behavior::Fail(error) => {
                AdversarialScript::returning(serde_json::Value::Null).failing_with(error)
            }
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
