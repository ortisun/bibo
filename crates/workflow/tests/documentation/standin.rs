//! Stand-ins for the stages around the two under test.
//!
//! The stages before the implementation stage store the deliverables the real ones would (the
//! plan, the specification, the architecture and the repository map). The validation stage stand-in
//! writes the evidence document the real validation stage writes (`validation-evidence`, with the
//! gate reports and the binding), with the outcome a test asks for. The real validation stage has
//! its own tests, in `tests/validation`.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::contracts::{Contract, GateReport, StageContract};
use factory_domain::ids::GateReportId;
use factory_domain::scope::TenantScope;
use factory_domain::values::{GitSha, MediaType, Sha256Digest, Slug};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::paths::CommitSha;
use factory_workflow::gates::framework::GateDecision;
use factory_workflow::handlers::{
    ContractContext, GateContext, HandlerRegistry, NamedArtifact, OutputDocument, StageContext,
    StageError, StageHandler, StageOutput,
};
use factory_workflow::stages::intake::common::{
    ContractBudget, ContractCriterion, ContractDeliverable, ContractInput, ContractSpec, Executor,
    GateDefinition, GateFacts, GateSubject, gate_report, stage_contract,
};
use factory_workflow::stages::validation::Binding;
use serde_json::{Value, json};

use crate::rig::{Log, Options, SPECIFICATION, definition_commit, lock, note};
use crate::support::world::World;

/// What the validation stand-in reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValidationMode {
    /// Every gate passed.
    AllPass,
    /// The tests failed. The stage run fails its gate, as the real one does.
    UnitTestsFail,
    /// The stored evidence holds a failed test gate while the stage run itself passes, as after a
    /// person overrode the block. The review stage must not be fooled by the second.
    EvidenceHidesFailure,
    /// The evidence is bound to another commit than the one that was built.
    StaleHead,
}

const GATE: &str = "standin-gate";
const GATE_TEXT: &str = "standin-gate 1.0.0: a stand-in stage stored its deliverables.";

fn subject(
    ctx_ids: &dyn factory_ports::clock::IdGenerator,
    clock: &dyn factory_ports::clock::Clock,
    job: factory_domain::ids::JobId,
    run: factory_domain::ids::StageRunId,
    attempt: factory_domain::ids::AttemptId,
    mode: factory_domain::vocabulary::ExecutionMode,
) -> GateSubject {
    let now = clock.now();
    GateSubject {
        job,
        stage_run: run,
        attempt,
        mode,
        report_id: GateReportId::from_uuid(ctx_ids.new_uuid()),
        started_at: now,
        finished_at: clock.now(),
    }
}

fn facts(
    id: &'static str,
    text: &'static str,
    outcome: &'static str,
    reason: &str,
    failures: Vec<(String, String)>,
) -> GateFacts {
    GateFacts {
        definition: GateDefinition {
            id,
            version: "1.0.0",
            text,
            commit: definition_commit(),
        },
        outcome,
        title: reason.to_owned(),
        reason: reason.to_owned(),
        failures,
        blocked: None,
        fidelity: "fake",
        executor: Executor::InProcess,
        commands: Vec::new(),
        tools: vec![("standin".to_owned(), "1.0.0".to_owned())],
        evidence: vec![format!("{id}={outcome}")],
    }
}

fn input(ctx: &ContractContext<'_>) -> ContractInput {
    ContractInput {
        name: "policy-bundle",
        description: "The hash of the policy bundle in force.",
        sha256: ctx.policy_hash.clone(),
        media_type: "application/json",
        source: "policy",
        produced_by: None,
        commit_sha: None,
        retrieved_at: ctx.now,
        trust: "trusted_internal",
    }
}

fn contract_of(
    ctx: &ContractContext<'_>,
    contract_id: &'static str,
    span: &'static str,
    deliverables: Vec<ContractDeliverable>,
    inputs: Vec<ContractInput>,
    gates: Vec<&'static str>,
) -> Result<StageContract, StageError> {
    stage_contract(&ContractSpec {
        kind: ctx.identity.kind,
        job: ctx.identity.job,
        stage_run: ctx.identity.stage_run,
        mode: ctx.mode,
        created_at: ctx.now,
        contract_id,
        title: "Stand in for a stage in a test",
        purpose: "Store the deliverables that the real stage would store, so that a stage under test has its inputs.",
        problem: "The stage under test reads what the stages before it produced, and those stages are not under test here.",
        inputs,
        preconditions: vec![(
            "upstream-passed",
            "The stages before this one passed.",
            "upstream_stage_passed",
        )],
        method: (
            "Store a fixed document",
            "A test needs the input to be exactly what it chose.",
            "Run the real stage",
            "The real stage has its own tests.",
        ),
        agent: ("standin".to_owned(), "1.0.0"),
        granted_tools: Vec::new(),
        shell: "none",
        placement: None,
        deliverables,
        criteria: gates
            .iter()
            .map(|gate| ContractCriterion {
                id: "standin-criterion",
                description: "The stand-in stored its deliverables.",
                gate,
            })
            .take(1)
            .collect(),
        gates,
        budget: ContractBudget {
            wall_time_seconds: 300,
            max_tokens: 0,
            max_cost_usd: 0.0,
            attempt_timeout_seconds: 240,
            max_attempts: 1,
        },
        rollback: "Nothing outside the test is changed.",
        span_name: span,
    })
}

/// Stores fixed deliverables.
pub struct Fixed {
    pub kind: StageKind,
    pub contract_id: &'static str,
    pub span: &'static str,
    pub deliverables: Vec<(&'static str, Vec<u8>)>,
}

#[async_trait]
impl StageHandler for Fixed {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    fn kind(&self) -> StageKind {
        self.kind
    }
    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        contract_of(
            ctx,
            self.contract_id,
            self.span,
            self.deliverables
                .iter()
                .map(|(name, _)| ContractDeliverable {
                    name,
                    description: "A fixed document.",
                    media_type: "application/json",
                    required: true,
                })
                .collect(),
            vec![input(ctx)],
            vec![GATE],
        )
    }
    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        let mut stored = Vec::new();
        for (name, bytes) in &self.deliverables {
            let artifact = ctx
                .ports
                .artifacts
                .put(
                    bytes.clone(),
                    MediaType::parse("application/json").map_err(|_| StageError::Internal)?,
                )
                .await
                .map_err(|_| StageError::Tool)?;
            stored.push(NamedArtifact {
                name: Slug::parse(name).map_err(|_| StageError::Internal)?,
                artifact,
            });
        }
        Ok(StageOutput {
            artifacts: stored,
            ..StageOutput::default()
        })
    }
    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        let report = gate_report(
            &subject(
                ctx.ports.ids,
                ctx.ports.clock,
                ctx.identity.job,
                ctx.identity.stage_run,
                ctx.attempt,
                ctx.mode,
            ),
            &facts(
                GATE,
                GATE_TEXT,
                "PASSED",
                "The stand-in stored its deliverables.",
                Vec::new(),
            ),
        )?;
        Ok(GateDecision {
            reports: vec![report],
            ..GateDecision::default()
        })
    }
}

/// Stores the evidence of the validation stage, with the outcome a test chose.
pub struct StandInValidation {
    pub mode: Arc<Mutex<ValidationMode>>,
    /// How many times the stage ran. A failing run names a different test each time, so that two
    /// rounds do not fail in the same way, which the engine reads as stagnation.
    pub rounds: std::sync::atomic::AtomicU32,
}

const UNIT_TESTS: &str = "unit-tests";
const BINDING_GATE: &str = "evidence-binding";
const UNIT_TESTS_TEXT: &str = "unit-tests 1.0.0: the tests run and every one that ran passed.";
const BINDING_TEXT: &str = "evidence-binding 1.0.0: the evidence is about this commit.";
const EVIDENCE: &str = "validation-evidence";

fn reports(
    ctx: &StageContext<'_>,
    unit_tests_pass: bool,
    round: u32,
) -> Result<Vec<GateReport>, StageError> {
    let make = |id: &'static str, text: &'static str, pass: bool| {
        gate_report(
            &subject(
                ctx.ports.ids,
                ctx.ports.clock,
                ctx.identity.job,
                ctx.identity.stage_run,
                ctx.attempt,
                ctx.mode,
            ),
            &facts(
                id,
                text,
                if pass { "PASSED" } else { "FAILED" },
                if pass {
                    "The gate passed."
                } else {
                    "One of the tests failed in the run."
                },
                if pass {
                    Vec::new()
                } else {
                    vec![(
                        format!("unit-test-failed-{round}"),
                        format!("The test counts_a_line_{round} failed in the verify run."),
                    )]
                },
            ),
        )
    };
    Ok(vec![
        make(UNIT_TESTS, UNIT_TESTS_TEXT, unit_tests_pass)?,
        make(BINDING_GATE, BINDING_TEXT, true)?,
    ])
}

#[async_trait]
impl StageHandler for StandInValidation {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    fn kind(&self) -> StageKind {
        StageKind::Validation
    }
    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        let (run, artifact) = ctx
            .upstream
            .iter()
            .rev()
            .filter(|run| run.kind == StageKind::Implementation)
            .find_map(|run| {
                run.outputs
                    .iter()
                    .find(|o| o.name.as_str() == "implementation-result")
                    .map(|o| (run, o.artifact.clone()))
            })
            .ok_or(StageError::Blocked(
                factory_domain::contracts::gate_report::BlockedCode::DependencyUnavailable,
            ))?;
        contract_of(
            ctx,
            "stage-contract.validation",
            "stage.validation",
            vec![ContractDeliverable {
                name: EVIDENCE,
                description: "The gate reports and the binding.",
                media_type: "application/json",
                required: true,
            }],
            vec![
                ContractInput {
                    name: "implementation-result",
                    description: "The commits to verify.",
                    sha256: artifact.sha256,
                    media_type: "application/json",
                    source: "previous_stage",
                    produced_by: Some(run.id),
                    commit_sha: None,
                    retrieved_at: ctx.now,
                    trust: "trusted_internal",
                },
                input(ctx),
            ],
            vec![UNIT_TESTS, BINDING_GATE],
        )
    }
    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        let mode = *lock(&self.mode);
        let find = |name: &str| {
            ctx.contract
                .inputs
                .iter()
                .find(|i| i.name.as_str() == name)
                .map(|i| i.artifact.clone())
        };
        let result_ref = find("implementation-result").ok_or(StageError::Internal)?;
        let policy = find("policy-bundle").ok_or(StageError::Internal)?;
        let bytes = ctx
            .ports
            .artifacts
            .get(&TenantScope::new(ctx.identity.tenant), &result_ref)
            .await
            .map_err(|_| StageError::Tool)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| StageError::Internal)?;
        let sha = |name: &str| {
            GitSha::parse(value[name].as_str().unwrap_or_default())
                .map_err(|_| StageError::Internal)
        };
        let base = sha("base_commit")?;
        let head = match mode {
            ValidationMode::StaleHead => base.clone(),
            _ => sha("head_commit")?,
        };
        let binding = Binding {
            implementation_result: result_ref.sha256.clone(),
            base_commit: base,
            head_commit: head,
            policy_hash: policy.sha256,
            image_digest: Sha256Digest::of(b"image"),
            definition_hash: Sha256Digest::of(b"definitions"),
        };
        let pass = matches!(mode, ValidationMode::AllPass | ValidationMode::StaleHead);
        let round = self
            .rounds
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let listed: Vec<Value> = reports(ctx, pass, round)?
            .iter()
            .map(|r| r.to_json_value().map_err(|_| StageError::Internal))
            .collect::<Result<_, _>>()?;
        Ok(StageOutput {
            documents: vec![OutputDocument {
                name: Slug::parse(EVIDENCE).map_err(|_| StageError::Internal)?,
                contract: None,
                media_type: MediaType::parse("application/json")
                    .map_err(|_| StageError::Internal)?,
                value: json!({
                    "kind": EVIDENCE,
                    "binding": binding.to_json(),
                    "policy_violation": false,
                    "reports": listed,
                }),
            }],
            ..StageOutput::default()
        })
    }
    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        let mode = *lock(&self.mode);
        let stored = ctx
            .outputs
            .iter()
            .find(|o| o.name.as_str() == EVIDENCE)
            .ok_or(StageError::InvalidOutput)?;
        let bytes = ctx
            .ports
            .artifacts
            .get(&TenantScope::new(ctx.identity.tenant), &stored.artifact)
            .await
            .map_err(|_| StageError::Tool)?;
        let document: Value = serde_json::from_slice(&bytes).map_err(|_| StageError::Internal)?;
        let mut reports: Vec<GateReport> = Vec::new();
        for value in document["reports"].as_array().ok_or(StageError::Internal)? {
            reports.push(
                GateReport::from_json_value(value.clone()).map_err(|_| StageError::Internal)?,
            );
        }
        if mode == ValidationMode::EvidenceHidesFailure {
            // The stage run itself passes: the reports it hands the engine are the passing ones.
            let make = |id: &'static str, text: &'static str| {
                gate_report(
                    &subject(
                        ctx.ports.ids,
                        ctx.ports.clock,
                        ctx.identity.job,
                        ctx.identity.stage_run,
                        ctx.attempt,
                        ctx.mode,
                    ),
                    &facts(id, text, "PASSED", "The gate passed.", Vec::new()),
                )
            };
            reports = vec![
                make(UNIT_TESTS, UNIT_TESTS_TEXT)?,
                make(BINDING_GATE, BINDING_TEXT)?,
            ];
        }
        Ok(GateDecision {
            reports,
            ..GateDecision::default()
        })
    }
}

/// Registers the stand-ins for every stage in the scope that the rig does not test.
pub fn register_around(
    handlers: &mut HandlerRegistry,
    world: &World,
    options: &Options,
    base: &CommitSha,
    _artifacts: Arc<crate::rig::Granting>,
    log: Log,
) -> Arc<Mutex<ValidationMode>> {
    let _ = world;
    note(&log, "rig.standins");
    let fixed = |kind: StageKind,
                 contract_id: &'static str,
                 span: &'static str,
                 deliverables: Vec<(&'static str, Vec<u8>)>| {
        Arc::new(Fixed {
            kind,
            contract_id,
            span,
            deliverables,
        })
    };
    let map = serde_json::to_vec(&json!({ "commit_sha": base.as_str() })).expect("serializes");
    let table: Vec<Arc<Fixed>> = vec![
        fixed(
            StageKind::Intake,
            "stage-contract.intake",
            "stage.intake",
            vec![(
                "normalized-request",
                b"{\"title\":\"Add a json flag\"}".to_vec(),
            )],
        ),
        fixed(
            StageKind::DomainDiscovery,
            "stage-contract.domain-discovery",
            "stage.domain_discovery",
            vec![(
                "domain-profile",
                b"{\"profile\":\"general-software\"}".to_vec(),
            )],
        ),
        fixed(
            StageKind::RepositoryIntelligence,
            "stage-contract.repository-intelligence",
            "stage.repository_intelligence",
            vec![("repository-map", map)],
        ),
        fixed(
            StageKind::Specification,
            "stage-contract.specification",
            "stage.specification",
            vec![("specification-contract", SPECIFICATION.as_bytes().to_vec())],
        ),
        fixed(
            StageKind::Architecture,
            "stage-contract.architecture",
            "stage.architecture",
            vec![(
                "architecture-design",
                b"{\"title\":\"A small command line tool with an output module.\"}".to_vec(),
            )],
        ),
        fixed(
            StageKind::TaskPlanning,
            "stage-contract.task-planning",
            "stage.task_planning",
            vec![("task-plan", options.plan.as_bytes().to_vec())],
        ),
    ];
    for handler in table {
        if options.scope.contains(&handler.kind) {
            handlers.register(handler).expect("one handler per stage");
        }
    }
    let mode = Arc::new(Mutex::new(options.validation));
    if options.scope.contains(&StageKind::Validation) {
        handlers
            .register(Arc::new(StandInValidation {
                mode: mode.clone(),
                rounds: std::sync::atomic::AtomicU32::new(0),
            }))
            .expect("one handler per stage");
    }
    mode
}
