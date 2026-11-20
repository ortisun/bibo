//! A stage handler whose behavior a test scripts, one attempt at a time.
//!
//! Every stage uses the same handler type with its own script. The handler resolves a contract
//! from the schema example, so the contract is a real, validated `StageContract`. It reports
//! fidelity `fake`, which a production engine refuses.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::contracts::{ArtifactRef, Contract, GateReport, ReviewVerdict, StageContract};
use factory_domain::values::{HumanText, MediaType, Sha256Digest, Slug};
use factory_domain::vocabulary::RiskTier;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::agent::{
    CostMicroUsd, Denial, ProbedCapabilities, RoutingNeed, RuntimeCapabilities, RuntimeId, Usage,
};
use factory_ports::registry::ContractKind;
use factory_workflow::audit::AuditAction;
use factory_workflow::gates::framework::GateDecision;
use factory_workflow::handlers::{
    Applicability, ContractContext, GateContext, NamedArtifact, NeedsHumanRequest, OutputDocument,
    SandboxReady, SkipBasis, SkipRule, StageContext, StageError, StageHandler, StageOutput,
};
use serde_json::{Value, json};

/// What one call to `execute` does.
#[derive(Clone)]
pub enum Step {
    /// Returns a valid output.
    Succeed,
    /// Returns the deliverable as an artifact that a tool made, instead of as a document: a blob
    /// that was written to the artifact store with `put`, and not indexed for the tenant.
    SucceedWithStoredArtifact,
    /// Returns the deliverable as an artifact that was never written to the artifact store.
    SucceedWithUnstoredArtifact,
    /// Returns this error.
    Fail(StageError),
    /// Returns a structured request for a person.
    NeedsHuman,
    /// Returns a document that the validator refuses.
    InvalidDocument,
    /// Waits until the notify is set, then returns a valid output. The wait ends early if the
    /// engine cancels the attempt.
    Hang(Arc<tokio::sync::Notify>),
}

/// What one call to `evaluate` hands over as gate evidence.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Eval {
    /// A passing report of the scripted gate.
    Pass,
    /// A passing report, and the handler says it supports the sandbox assurance level.
    PassClaimingAssurance,
    /// A failing report. The text is the id of the failed check.
    Fail(&'static str),
    /// A report of a gate that could not run.
    Blocked,
    /// The scripted gate passes, and each of these gates reports `BLOCKED` with the given block
    /// code, as `(gate id, block code)`. The block of the stage run is then those gates and codes.
    BlockedAt(&'static [(&'static str, &'static str)]),
    /// Nothing at all: the nearest thing to an agent saying "it passed".
    NoEvidence,
    /// A passing report and a verdict that asks for changes of this defect class.
    ChangesRequired(&'static str),
    /// A passing report and a verdict that asks a person.
    ReviewerNeedsHuman,
    /// A passing report, and the gate itself asks a person.
    HumanGate,
    /// A passing report, and a deterministic check found a policy violation.
    PolicyViolation,
    /// A report that claims another stage run.
    WrongStageRun,
    /// The gate cannot run: the handler reports a missing tool.
    CannotRun,
}

/// The retry-related fields of the contract the handler resolves.
#[derive(Clone)]
pub struct Tweaks {
    pub max_attempts: i64,
    pub retry_on: Vec<&'static str>,
    pub backoff_initial_ms: i64,
    pub backoff_max_ms: i64,
    pub attempt_timeout_seconds: i64,
    /// Adds an acceptance criterion that names a gate which never reports, so a pass has a
    /// criterion with no evidence behind it.
    pub uncovered_criterion: bool,
}

impl Default for Tweaks {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            retry_on: vec![
                "TOOL_ERROR",
                "INVALID_OUTPUT",
                "PROVIDER_ERROR",
                "SANDBOX_ERROR",
                "TIMED_OUT",
                "LEASE_LOST",
            ],
            backoff_initial_ms: 5_000,
            backoff_max_ms: 300_000,
            attempt_timeout_seconds: 900,
            uncovered_criterion: false,
        }
    }
}

/// What the handler did, for the test to read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executed {
    pub attempt_number: u32,
}

/// The script of one stage.
pub struct Script {
    pub steps: VecDeque<Step>,
    pub otherwise: Step,
    pub skip: Option<SkipRule>,
    pub tweaks: Tweaks,
    pub executed: Vec<Executed>,
    /// Whether the stage runs an agent, so the engine issues a job token for it.
    pub agent: bool,
    /// What the stage spends through its token, in millionths of a US dollar.
    pub spend_micro_usd: u64,
    /// The broker that meters the spend.
    pub broker: Option<std::sync::Arc<factory_testkit::broker::FakeModelBroker>>,
    /// The token each call of `execute` was given.
    pub tokens: Vec<Option<factory_ports::agent::JobTokenId>>,
    /// Audit actions that `execute` notes, as a stage that runs commands and sandboxes would.
    pub notes: Vec<AuditAction>,
    /// Tool calls that policy denied during `execute`.
    pub denials: u32,
    /// What the next calls to `evaluate` hand over, in order.
    pub evals: VecDeque<Eval>,
    /// What `evaluate` hands over once the queue is empty.
    pub eval_otherwise: Eval,
    /// How many times `evaluate` ran.
    pub evaluated: u32,
    /// Whether `execute` says that its sandbox is ready. A stage that runs no sandbox may not.
    pub report_sandbox: bool,
    /// Whether the output carries a document the contract does not declare.
    pub extra_document: bool,
    /// Whether the output leaves out the required deliverable.
    pub omit_deliverable: bool,
    /// The document a succeeding attempt returns, in place of `{ "stage": ... }`. A test that
    /// needs the engine to read something out of a stage's output sets it.
    pub document: Option<Value>,
    /// What a failing run leaves behind: the number of denied tool calls and whether it stored a
    /// transcript. The handler reports them with `note_failed_run` before it returns the error.
    pub failed_run: Option<(u32, bool)>,
    /// The transcripts that failing runs stored, so a test can ask whether the engine kept them.
    pub transcripts: Vec<factory_domain::contracts::ArtifactRef>,
    /// Whether `execute` starts an agent run through `ctx.ports.runtime`, as the stages that run
    /// an agent do. What the run reports is what the test queued in the fake runtime.
    pub run_agent: bool,
    /// Whether a successful `execute` stores a transcript and notes it, and `evaluate` then reads
    /// it back for the tenant, as the specification gate does. The read's outcome is kept here.
    pub gate_reads_transcript: bool,
    /// What the gate's read of the noted transcript gave: `Some(true)` when it read it back.
    pub transcript_read: Option<bool>,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            steps: VecDeque::new(),
            otherwise: Step::Succeed,
            skip: None,
            tweaks: Tweaks::default(),
            executed: Vec::new(),
            agent: false,
            notes: Vec::new(),
            denials: 0,
            spend_micro_usd: 0,
            broker: None,
            tokens: Vec::new(),
            evals: VecDeque::new(),
            eval_otherwise: Eval::Pass,
            evaluated: 0,
            report_sandbox: true,
            extra_document: false,
            omit_deliverable: false,
            document: None,
            failed_run: None,
            transcripts: Vec::new(),
            run_agent: false,
            gate_reads_transcript: false,
            transcript_read: None,
        }
    }
}

/// A shared handle to a script, so the test can change it while the engine holds the handler.
#[derive(Clone, Default)]
pub struct ScriptHandle(Arc<Mutex<Script>>);

impl ScriptHandle {
    pub fn with<T>(&self, change: impl FnOnce(&mut Script) -> T) -> T {
        change(&mut self.0.lock().expect("the lock is never poisoned"))
    }

    /// Queues what the next attempts do, in order.
    pub fn queue(&self, steps: impl IntoIterator<Item = Step>) {
        self.with(|script| script.steps.extend(steps));
    }

    /// What the attempts do once the queue is empty.
    pub fn otherwise(&self, step: Step) {
        self.with(|script| script.otherwise = step);
    }

    /// Makes the stage not apply, by a deterministic rule.
    pub fn skip_by_rule(&self, rule: &str) {
        self.with(|script| {
            script.skip = Some(SkipRule {
                basis: SkipBasis::DeterministicRule,
                rule: Slug::parse(rule).expect("a slug"),
                inputs: HumanText::parse("the change touches no code and only documents")
                    .expect("a text"),
            });
        });
    }

    /// Makes the stage note these audit actions, as a handler does for what only it sees.
    pub fn notes(&self, actions: &[AuditAction]) {
        self.with(|script| script.notes = actions.to_vec());
    }

    /// Makes the stage report this many denied tool calls.
    pub fn denials(&self, count: u32) {
        self.with(|script| script.denials = count);
    }

    /// Makes the stage run an agent that spends this much through its job token.
    pub fn agent_spending(&self, micro_usd: u64) {
        self.with(|script| {
            script.agent = true;
            script.spend_micro_usd = micro_usd;
        });
    }

    /// Makes `execute` start one agent run through the ports it was given, in a fake sandbox. The
    /// run does what the script queued in `World::runtime` says.
    pub fn runs_an_agent(&self) {
        self.with(|script| script.run_agent = true);
    }

    /// Makes `execute` store and note a transcript, and the gate read it back for the tenant.
    pub fn gate_reads_a_transcript(&self) {
        self.with(|script| script.gate_reads_transcript = true);
    }

    /// Whether the gate read the noted transcript back: `None` before any gate ran.
    pub fn transcript_read(&self) -> Option<bool> {
        self.with(|script| script.transcript_read)
    }

    /// The tokens the stage was given, one for each attempt.
    pub fn tokens(&self) -> Vec<Option<factory_ports::agent::JobTokenId>> {
        self.with(|script| script.tokens.clone())
    }

    /// Queues what the next gate evaluations hand over, in order.
    pub fn queue_evals(&self, evals: impl IntoIterator<Item = Eval>) {
        self.with(|script| script.evals.extend(evals));
    }

    /// What gate evaluations hand over once the queue is empty.
    pub fn evals_otherwise(&self, eval: Eval) {
        self.with(|script| script.eval_otherwise = eval);
    }

    /// How many times the gate was evaluated.
    pub fn evaluated(&self) -> u32 {
        self.with(|script| script.evaluated)
    }

    /// The attempt numbers that ran `execute`, in order.
    pub fn executed(&self) -> Vec<u32> {
        self.with(|script| script.executed.iter().map(|e| e.attempt_number).collect())
    }
}

/// The handler of one stage.
pub struct ScriptedHandler {
    kind: StageKind,
    script: ScriptHandle,
}

impl ScriptedHandler {
    pub fn new(kind: StageKind, script: ScriptHandle) -> Self {
        Self { kind, script }
    }
}

/// Starts one agent run the way a stage does: in a sandbox from the sandbox port, through the
/// runtime of the ports it was given. The request names the attempt being run.
async fn run_an_agent(ctx: &StageContext<'_>) {
    use factory_ports::sandbox::{SandboxProfile, TeardownReason};
    use factory_testkit::fixtures::{Ids, agent_run_request, sandbox_spec};
    let ids = Ids::new();
    let mut session = ctx
        .ports
        .sandbox
        .create_verified(sandbox_spec(&ids, SandboxProfile::Agent), ctx.cancel)
        .await
        .expect("the fake sandbox starts");
    let mut request = agent_run_request(&ids);
    request.attempt = ctx.attempt;
    let _report = ctx
        .ports
        .runtime
        .run(&mut *session, request, ctx.cancel)
        .await;
    let _ = session.stop_and_remove(TeardownReason::Completed).await;
}

const EXAMPLE: &str =
    include_str!("../../../../schemas/examples/stage-contract/valid/specification-stage.json");

fn resolve_contract(ctx: &ContractContext<'_>, tweaks: &Tweaks) -> StageContract {
    let mut doc: Value = serde_json::from_str(EXAMPLE).expect("the example is JSON");
    let metadata = doc["metadata"].as_object_mut().expect("metadata");
    metadata.insert("stage_kind".into(), json!(ctx.identity.kind.as_str()));
    metadata.insert("job_id".into(), json!(ctx.identity.job.to_string()));
    metadata.insert(
        "stage_run_id".into(),
        json!(ctx.identity.stage_run.to_string()),
    );
    metadata.insert("execution_mode".into(), json!(ctx.mode.as_str()));
    metadata.remove("attempt_id");
    doc["evaluator"] = json!({ "kind": "deterministic_gate", "gate_ids": ["scripted-gate"] });
    doc["acceptance_criteria"] = json!([{
        "id": "scripted-check",
        "description": "The scripted gate reports that the stage did its work.",
        "machine_verifiable": true,
        "verification": { "kind": "gate", "ref": "scripted-gate" }
    }]);
    if tweaks.uncovered_criterion
        && let Some(criteria) = doc["acceptance_criteria"].as_array_mut()
    {
        criteria.push(json!({
            "id": "unverified-check",
            "description": "A check that no gate of this stage ever reports on.",
            "machine_verifiable": true,
            "verification": { "kind": "gate", "ref": "silent-gate" }
        }));
    }
    doc["deliverables"] = json!([{
        "name": "scripted-output",
        "description": "The document the scripted stage produces.",
        "media_type": "application/json",
        "required": true
    }]);
    doc["timeout_and_retries"] = json!({
        "attempt_timeout_seconds": tweaks.attempt_timeout_seconds,
        "max_attempts": tweaks.max_attempts,
        "backoff": { "initial_ms": tweaks.backoff_initial_ms, "max_ms": tweaks.backoff_max_ms, "jitter": "none" },
        "retry_on": tweaks.retry_on,
        "max_rework_iterations": 2
    });
    StageContract::from_json_value(doc).expect("the scripted contract is valid")
}

#[async_trait]
impl StageHandler for ScriptedHandler {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    fn kind(&self) -> StageKind {
        self.kind
    }

    fn routing_need(&self, ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        self.script
            .with(|script| script.agent)
            .then(|| RoutingNeed {
                stage: ctx.identity.kind,
                tier: RecommendedTier::Standard,
                required: Vec::new(),
                risk: RiskTier::Low,
                exclude: Vec::new(),
                // The router considers only a runtime that was probed. The scripted stage
                // stands for the probe of the one fake runtime.
                probed: ProbedCapabilities(BTreeMap::from([(
                    RuntimeId::new("fake").expect("a runtime"),
                    RuntimeCapabilities {
                        runtime_version: "fake".to_owned(),
                        observations: Vec::new(),
                    },
                )])),
                author: None,
            })
    }

    fn applicability(&self, _ctx: &ContractContext<'_>) -> Applicability {
        match self.script.with(|script| script.skip.clone()) {
            Some(rule) => Applicability::NotApplicable(rule),
            None => Applicability::Applies,
        }
    }

    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        let tweaks = self.script.with(|script| script.tweaks.clone());
        Ok(resolve_contract(ctx, &tweaks))
    }

    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        let (report, extra, omit, denials, scripted_document) = self.script.with(|script| {
            (
                script.report_sandbox,
                script.extra_document,
                script.omit_deliverable,
                script.denials,
                script.document.clone(),
            )
        });
        if report {
            ctx.report_sandbox_ready(SandboxReady {
                posture_verified: true,
                tool_grants_recorded: true,
                probe_satisfies_stage: true,
            });
        }
        self.script.with(|script| {
            for action in &script.notes {
                ctx.note_audit(*action);
            }
            script.tokens.push(ctx.job_token.map(|token| token.id));
            if let (Some(broker), Some(token)) = (&script.broker, ctx.job_token)
                && script.spend_micro_usd > 0
            {
                broker.meter(
                    &token.id,
                    Usage {
                        cost: CostMicroUsd(script.spend_micro_usd),
                        requests: 1,
                        ..Usage::default()
                    },
                );
            }
        });
        if self.script.with(|script| script.run_agent) {
            run_an_agent(ctx).await;
        }
        if self.script.with(|script| script.gate_reads_transcript) {
            // As the runtime does: the blob is stored, nobody indexes it for the tenant, and the
            // handler notes it for the engine.
            let transcript = ctx
                .ports
                .artifacts
                .put(
                    b"{\"type\":\"result\"}\n".to_vec(),
                    MediaType::parse("text/plain").expect("a media type"),
                )
                .await
                .expect("the transcript is stored");
            ctx.note_transcript(&transcript);
            self.script
                .with(|script| script.transcripts.push(transcript.clone()));
        }
        let step = self.script.with(|script| {
            script.executed.push(Executed {
                attempt_number: ctx.attempt_number,
            });
            script
                .steps
                .pop_front()
                .unwrap_or_else(|| script.otherwise.clone())
        });
        let name = if extra {
            "unlisted-output"
        } else {
            "scripted-output"
        };
        let document = |value: Value| OutputDocument {
            name: Slug::parse(name).expect("a slug"),
            contract: Some((ContractKind::ReviewVerdict, 1)),
            media_type: MediaType::parse("application/json").expect("a media type"),
            value,
        };
        let documents = |value: Value| {
            if omit {
                Vec::new()
            } else {
                vec![document(value)]
            }
        };
        match step {
            Step::Succeed => Ok(StageOutput {
                documents: documents(
                    scripted_document
                        .unwrap_or_else(|| json!({ "stage": ctx.identity.kind.as_str() })),
                ),
                usage: Usage::default(),
                permission_denials: (0..denials)
                    .map(|_| Denial {
                        tool: "write-file".to_owned(),
                        reason: "the path is protected".to_owned(),
                    })
                    .collect(),
                ..StageOutput::default()
            }),
            Step::SucceedWithStoredArtifact | Step::SucceedWithUnstoredArtifact => {
                let artifact = if matches!(step, Step::SucceedWithStoredArtifact) {
                    ctx.ports
                        .artifacts
                        .put(
                            br#"{"made":"by a tool"}"#.to_vec(),
                            MediaType::parse("application/json").expect("a media type"),
                        )
                        .await
                        .expect("the artifact is stored")
                } else {
                    ArtifactRef {
                        sha256: Sha256Digest::of(b"a blob that was never stored"),
                        media_type: MediaType::parse("application/json").expect("a media type"),
                        size_bytes: None,
                    }
                };
                Ok(StageOutput {
                    artifacts: vec![NamedArtifact {
                        name: Slug::parse(name).expect("a slug"),
                        artifact,
                    }],
                    ..StageOutput::default()
                })
            }
            Step::Fail(error) => {
                let failed = self.script.with(|script| script.failed_run);
                if let Some((denied, transcript)) = failed {
                    let stored = if transcript {
                        let reference = ctx
                            .ports
                            .artifacts
                            .put(
                                b"the redacted transcript of a run that failed".to_vec(),
                                MediaType::parse("text/plain").expect("a media type"),
                            )
                            .await
                            .expect("the transcript is stored");
                        self.script
                            .with(|script| script.transcripts.push(reference.clone()));
                        Some(reference)
                    } else {
                        None
                    };
                    ctx.note_failed_run(&factory_ports::agent::AgentRunReport {
                        outcome: Err(factory_ports::agent::AgentRunError::Timeout),
                        transcript: stored,
                        usage: Usage::default(),
                        runtime_version: None,
                        exit: None,
                        permission_denials: (0..denied)
                            .map(|_| Denial {
                                tool: "write-file".to_owned(),
                                reason: "the path is protected".to_owned(),
                            })
                            .collect(),
                    });
                }
                Err(error)
            }
            Step::NeedsHuman => Ok(StageOutput {
                needs_human: Some(NeedsHumanRequest {
                    reason: Slug::parse("ambiguous-requirement").expect("a slug"),
                }),
                ..StageOutput::default()
            }),
            Step::InvalidDocument => Ok(StageOutput {
                documents: documents(json!({ "invalid": true })),
                ..StageOutput::default()
            }),
            Step::Hang(release) => {
                tokio::select! {
                    () = release.notified() => {}
                    () = ctx.cancel.cancelled() => return Err(StageError::Cancelled),
                }
                Ok(StageOutput {
                    documents: documents(json!({ "stage": ctx.identity.kind.as_str() })),
                    ..StageOutput::default()
                })
            }
        }
    }

    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        let transcript = self.script.with(|script| {
            script
                .gate_reads_transcript
                .then(|| script.transcripts.last().cloned())
                .flatten()
        });
        if let Some(transcript) = transcript {
            let scope = factory_domain::scope::TenantScope::new(ctx.identity.tenant);
            let read = ctx.ports.artifacts.get(&scope, &transcript).await.is_ok();
            self.script
                .with(|script| script.transcript_read = Some(read));
            if !read {
                return Err(StageError::Blocked(
                    factory_domain::contracts::gate_report::BlockedCode::DependencyUnavailable,
                ));
            }
        }
        let eval = self.script.with(|script| {
            script.evaluated += 1;
            script.evals.pop_front().unwrap_or(script.eval_otherwise)
        });
        let pass = |ctx: &GateContext<'_>| report(ctx, "PASSED", "tests-pass");
        Ok(match eval {
            Eval::Pass => GateDecision {
                reports: vec![pass(ctx)],
                ..GateDecision::default()
            },
            Eval::PassClaimingAssurance => {
                let report = pass(ctx);
                GateDecision {
                    assurance: vec![
                        factory_workflow::gates::framework::decision::AssuranceClaim {
                            level: factory_domain::vocabulary::AssuranceLevel::VerifiedInSandbox,
                            gate: report.metadata.gate_id.clone(),
                        },
                    ],
                    reports: vec![report],
                    ..GateDecision::default()
                }
            }
            Eval::Fail(check) => GateDecision {
                reports: vec![report(ctx, "FAILED", check)],
                ..GateDecision::default()
            },
            Eval::Blocked => GateDecision {
                reports: vec![report(ctx, "BLOCKED", "scanner")],
                ..GateDecision::default()
            },
            Eval::BlockedAt(blocks) => {
                let mut reports = vec![pass(ctx)];
                reports.extend(
                    blocks
                        .iter()
                        .map(|(gate, code)| blocked_at(ctx, gate, code)),
                );
                GateDecision {
                    reports,
                    ..GateDecision::default()
                }
            }
            Eval::NoEvidence => GateDecision::default(),
            Eval::ChangesRequired(defect) => GateDecision {
                reports: vec![pass(ctx)],
                review: Some(verdict(ctx, "CHANGES_REQUIRED", defect)),
                ..GateDecision::default()
            },
            Eval::ReviewerNeedsHuman => GateDecision {
                reports: vec![pass(ctx)],
                review: Some(verdict(ctx, "NEEDS_HUMAN", "specification")),
                ..GateDecision::default()
            },
            Eval::HumanGate => GateDecision {
                reports: vec![pass(ctx)],
                human_gate: true,
                ..GateDecision::default()
            },
            Eval::PolicyViolation => GateDecision {
                reports: vec![pass(ctx)],
                policy_violation: true,
                ..GateDecision::default()
            },
            Eval::WrongStageRun => {
                let mut wrong = report(ctx, "PASSED", "tests-pass");
                wrong.metadata.stage_run_id =
                    factory_domain::ids::StageRunId::from_uuid(ctx.ports.ids.new_uuid());
                GateDecision {
                    reports: vec![wrong],
                    ..GateDecision::default()
                }
            }
            Eval::CannotRun => {
                return Err(StageError::Blocked(
                    factory_domain::contracts::gate_report::BlockedCode::ToolUnavailable,
                ));
            }
        })
    }
}

const PASSED_REPORT: &str =
    include_str!("../../../../schemas/examples/gate-report/valid/build-and-test-passed.json");
const BLOCKED_REPORT: &str = include_str!(
    "../../../../schemas/examples/gate-report/valid/security-scan-blocked-tool-missing.json"
);
const VERDICT: &str = include_str!(
    "../../../../schemas/examples/review-verdict/valid/changes-required-missing-test.json"
);

fn uuid_text(ctx: &GateContext<'_>) -> String {
    ctx.ports.ids.new_uuid().hyphenated().to_string()
}

/// A gate report for the scripted gate, about the stage run being judged.
fn report(ctx: &GateContext<'_>, outcome: &str, check: &str) -> GateReport {
    let mut doc: Value = serde_json::from_str(if outcome == "BLOCKED" {
        BLOCKED_REPORT
    } else {
        PASSED_REPORT
    })
    .expect("the example is JSON");
    let meta = doc["metadata"].as_object_mut().expect("metadata");
    meta.insert("gate_report_id".into(), json!(uuid_text(ctx)));
    meta.insert("gate_id".into(), json!("scripted-gate"));
    meta.insert("job_id".into(), json!(ctx.identity.job.to_string()));
    meta.insert(
        "stage_run_id".into(),
        json!(ctx.identity.stage_run.to_string()),
    );
    meta.insert("attempt_id".into(), json!(ctx.attempt.to_string()));
    meta.insert("execution_mode".into(), json!(ctx.mode.as_str()));
    doc["environment"]["fidelity"] = json!("fake");
    if outcome == "FAILED" {
        doc["outcome"] = json!("FAILED");
        doc["reason"] = json!("One check of the scripted gate failed on the job commit.");
        doc["commands"][0]["exit_code"] = json!(1);
        doc["failures"] = json!([{
            "check_id": check,
            "message": "The scripted check found a problem in the change."
        }]);
    }
    GateReport::from_json_value(doc).expect("a valid scripted report")
}

/// A report that another gate than the scripted one could not run, with a block code.
fn blocked_at(ctx: &GateContext<'_>, gate: &str, code: &str) -> GateReport {
    let mut doc: Value = serde_json::from_str(BLOCKED_REPORT).expect("the example is JSON");
    let meta = doc["metadata"].as_object_mut().expect("metadata");
    meta.insert("gate_report_id".into(), json!(uuid_text(ctx)));
    meta.insert("gate_id".into(), json!(gate));
    meta.insert("job_id".into(), json!(ctx.identity.job.to_string()));
    meta.insert(
        "stage_run_id".into(),
        json!(ctx.identity.stage_run.to_string()),
    );
    meta.insert("attempt_id".into(), json!(ctx.attempt.to_string()));
    meta.insert("execution_mode".into(), json!(ctx.mode.as_str()));
    doc["environment"]["fidelity"] = json!("fake");
    doc["blocked_reason"] = json!({"code": code, "missing": ["a recorded decision"]});
    GateReport::from_json_value(doc).expect("a valid scripted report")
}

/// A review verdict about the stage run being judged.
fn verdict(ctx: &GateContext<'_>, kind: &str, defect: &str) -> ReviewVerdict {
    let mut doc: Value = serde_json::from_str(VERDICT).expect("the example is JSON");
    let meta = doc["metadata"].as_object_mut().expect("metadata");
    meta.insert("review_id".into(), json!(uuid_text(ctx)));
    meta.insert("job_id".into(), json!(ctx.identity.job.to_string()));
    meta.insert(
        "stage_run_id".into(),
        json!(ctx.identity.stage_run.to_string()),
    );
    meta.insert("execution_mode".into(), json!(ctx.mode.as_str()));
    doc["metadata"]["reviewer"]["runtime"]["fidelity"] = json!("fake");
    doc["verdict"] = json!(kind);
    doc["findings"][0]["defect_class"] = json!(defect);
    if kind == "NEEDS_HUMAN" {
        doc["findings"] = json!([]);
        doc["human_question"] = json!("Is the unreadable file case in scope for this change?");
    }
    ReviewVerdict::from_json_value(doc).expect("a valid scripted verdict")
}
