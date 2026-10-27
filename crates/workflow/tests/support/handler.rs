//! A stage handler whose behavior a test scripts, one attempt at a time.
//!
//! Every stage uses the same handler type with its own script. The handler resolves a contract
//! from the schema example, so the contract is a real, validated `StageContract`. It reports
//! fidelity `fake`, which a production engine refuses.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::contracts::{Contract, GateReport, ReviewVerdict, StageContract};
use factory_domain::values::{HumanText, MediaType, Slug};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::agent::Usage;
use factory_ports::registry::ContractKind;
use factory_workflow::gates::framework::GateDecision;
use factory_workflow::handlers::{
    Applicability, ContractContext, GateContext, NeedsHumanRequest, OutputDocument, SandboxReady,
    SkipBasis, SkipRule, StageContext, StageError, StageHandler, StageOutput,
};
use serde_json::{Value, json};

/// What one call to `execute` does.
#[derive(Clone)]
pub enum Step {
    /// Returns a valid output.
    Succeed,
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
    /// A failing report. The text is the id of the failed check.
    Fail(&'static str),
    /// A report of a gate that could not run.
    Blocked,
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
}

impl Default for Script {
    fn default() -> Self {
        Self {
            steps: VecDeque::new(),
            otherwise: Step::Succeed,
            skip: None,
            tweaks: Tweaks::default(),
            executed: Vec::new(),
            evals: VecDeque::new(),
            eval_otherwise: Eval::Pass,
            evaluated: 0,
            report_sandbox: true,
            extra_document: false,
            omit_deliverable: false,
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
        let (report, extra, omit) = self.script.with(|script| {
            (
                script.report_sandbox,
                script.extra_document,
                script.omit_deliverable,
            )
        });
        if report {
            ctx.report_sandbox_ready(SandboxReady {
                started_within_limits: true,
                tool_grants_in_place: true,
                capability_probe_satisfied: true,
            });
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
                documents: documents(json!({ "stage": ctx.identity.kind.as_str() })),
                usage: Usage::default(),
                ..StageOutput::default()
            }),
            Step::Fail(error) => Err(error),
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
            Eval::Fail(check) => GateDecision {
                reports: vec![report(ctx, "FAILED", check)],
                ..GateDecision::default()
            },
            Eval::Blocked => GateDecision {
                reports: vec![report(ctx, "BLOCKED", "scanner")],
                ..GateDecision::default()
            },
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
