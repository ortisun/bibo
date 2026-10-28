//! The validation stage handler.
//!
//! `execute` runs the gates and writes the evidence. `evaluate` reads the stored evidence back,
//! checks that it is about this commit, this policy, this image and these definitions, and hands
//! the engine typed gate reports. Neither says that the stage passed.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::gate_report::{BlockedCode, DefinitionSource, TrustedDefinition};
use factory_domain::contracts::specification_contract::SpecStatus;
use factory_domain::contracts::{ArtifactRef, Contract, GateReport, StageContract};
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, Sha256Digest, Slug};
use factory_domain::vocabulary::{Fidelity, GateOutcome, StageKind};
use factory_ports::artifact::ArtifactStore;
use factory_ports::paths::{CommitSha, RepoPath};
use factory_ports::registry::ContractKind;
use factory_ports::workspace::{JobRepo, ReadView, WorkspaceError};
use serde_json::{Value, json};

use super::assemble::{Assembler, HostResult};
use super::binding::Binding;
use super::config::ValidationConfig;
use super::contract::{EVIDENCE, POLICY_INPUT, resolve};
use super::gather::gather;
use super::host;
use super::input::{
    Candidate, IMPLEMENTATION_RESULT, SPECIFICATION_CONTRACT, parse_candidate, parse_specification,
};
use super::sandboxed::{Io, Sandboxed, in_sandbox, workspace_error};
use super::set::{Findings, SpecState, reports};
use crate::gates::command::report::{ReportContext, ReportError, Subject, image_digest};
use crate::gates::command::{
    CommandGate, MANIFEST_JSON_PATH, MANIFEST_PATH, Resolved, Role, TrustedGates, gate_id,
};
use crate::gates::framework::GateDecision;
use crate::gates::scope::acceptance::Requirement;
use crate::handlers::{
    ContractContext, GateContext, OutputDocument, SandboxReady, StageContext, StageError,
    StageHandler, StageOutput,
};

/// The gates whose failure is a violation of policy that no one waives.
const NONWAIVABLE: [&str; 3] = [
    gate_id::PROTECTED_PATHS,
    gate_id::TEST_PROTECTION,
    gate_id::SECRET_SCAN,
];

/// The validation stage.
#[derive(Debug, Clone)]
pub struct ValidationHandler {
    cfg: Arc<ValidationConfig>,
}

impl ValidationHandler {
    /// A handler built from the composition root's configuration.
    #[must_use]
    pub fn new(cfg: Arc<ValidationConfig>) -> Self {
        Self { cfg }
    }
}

fn input_artifact(contract: &StageContract, name: &str) -> Option<ArtifactRef> {
    contract
        .inputs
        .iter()
        .find(|input| input.name.as_str() == name)
        .map(|input| input.artifact.clone())
}

fn fidelity(sandbox: Fidelity, workspaces: Fidelity, artifacts: Fidelity) -> Fidelity {
    if [sandbox, workspaces, artifacts].contains(&Fidelity::Fake) {
        Fidelity::Fake
    } else {
        Fidelity::Real
    }
}

fn report_error(_: ReportError) -> StageError {
    StageError::Internal
}

/// Why the gate definitions are not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unavailable {
    /// Neither manifest path exists at the base commit.
    Missing,
    /// The manifest is there and cannot be read or is not valid.
    Unreadable,
}

/// Reads the project manifest at the base commit and resolves the gates.
async fn load_definitions(
    repo: &dyn JobRepo,
    cfg: &ValidationConfig,
    base: &CommitSha,
) -> Result<Result<TrustedGates, Unavailable>, StageError> {
    for path in [MANIFEST_PATH, MANIFEST_JSON_PATH] {
        let Ok(path) = RepoPath::new(path) else {
            return Ok(Err(Unavailable::Unreadable));
        };
        match repo
            .read_file_at(
                base,
                &path,
                cfg.bounds.max_manifest_bytes,
                ReadView::Trusted,
            )
            .await
        {
            Ok(bytes) => {
                return Ok(match cfg.manifest.read(&bytes) {
                    Ok(manifest) => Ok(TrustedGates::resolve(
                        &manifest,
                        base.clone(),
                        &cfg.policy.commands,
                    )),
                    Err(_) => Err(Unavailable::Unreadable),
                });
            }
            Err(WorkspaceError::PathNotFound(_)) => {}
            Err(WorkspaceError::Cancelled) => return Err(StageError::Cancelled),
            Err(_) => return Ok(Err(Unavailable::Unreadable)),
        }
    }
    Ok(Err(Unavailable::Missing))
}

/// The hash recorded when the definitions are not available, so that the binding still has a
/// value for them and a later run with definitions does not match it.
fn unavailable_hash(reason: Unavailable) -> Sha256Digest {
    Sha256Digest::of(format!("definitions-unavailable:{reason:?}").as_bytes())
}

async fn read_candidate(
    artifacts: &dyn ArtifactStore,
    scope: &TenantScope,
    reference: &ArtifactRef,
) -> Result<Candidate, StageError> {
    let bytes = artifacts
        .get(scope, reference)
        .await
        .map_err(|_| StageError::Blocked(BlockedCode::DependencyUnavailable))?;
    parse_candidate(&bytes).ok_or(StageError::Blocked(BlockedCode::DependencyUnavailable))
}

async fn read_specification(
    artifacts: &dyn ArtifactStore,
    scope: &TenantScope,
    contract: &StageContract,
) -> SpecState {
    let Some(reference) = input_artifact(contract, SPECIFICATION_CONTRACT) else {
        return SpecState::Missing;
    };
    let Ok(bytes) = artifacts.get(scope, &reference).await else {
        return SpecState::Missing;
    };
    let Some(spec) = parse_specification(&bytes) else {
        return SpecState::Missing;
    };
    if spec.metadata.status != SpecStatus::Approved {
        return SpecState::NotApproved;
    }
    SpecState::Ready(
        spec.requirements
            .iter()
            .map(|requirement| Requirement {
                id: requirement.id.as_str().to_owned(),
                scenarios: requirement
                    .acceptance_scenario_ids
                    .iter()
                    .map(|id| id.as_str().to_owned())
                    .collect(),
            })
            .collect(),
    )
}

fn definition_of(
    base: &CommitSha,
    definitions: &Result<TrustedGates, Unavailable>,
) -> (TrustedDefinition, Sha256Digest) {
    let hash = match definitions {
        Ok(defs) => defs.hash().clone(),
        Err(reason) => unavailable_hash(*reason),
    };
    (
        TrustedDefinition {
            source: DefinitionSource::ProtectedBaseBranch,
            commit_sha: base.clone(),
            definition_sha256: hash.clone(),
        },
        hash,
    )
}

#[async_trait]
impl StageHandler for ValidationHandler {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn kind(&self) -> StageKind {
        StageKind::Validation
    }

    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        resolve(ctx)
    }

    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        let cfg = &*self.cfg;
        let ports = ctx.ports;
        let cancel = ctx.cancel;
        let contract = ctx.contract;
        let scope = TenantScope::new(ctx.identity.tenant);
        let subject = Subject {
            job: ctx.identity.job,
            stage_run: ctx.identity.stage_run,
            attempt: ctx.attempt,
            mode: ctx.mode,
        };

        let result_ref =
            input_artifact(contract, IMPLEMENTATION_RESULT).ok_or(StageError::Internal)?;
        let policy_hash = input_artifact(contract, POLICY_INPUT)
            .ok_or(StageError::Internal)?
            .sha256;
        let candidate = read_candidate(ports.artifacts, &scope, &result_ref).await?;
        let repo = ports
            .workspaces
            .repo(subject.job)
            .await
            .map_err(workspace_error)?;

        let definitions = load_definitions(&*repo, cfg, &candidate.base).await?;
        let (trusted, definition_hash) = definition_of(&candidate.base, &definitions);
        let image = image_digest(cfg.sandbox.image.reference()).map_err(report_error)?;
        let binding = Binding {
            implementation_result: result_ref.sha256.clone(),
            base_commit: candidate.base.clone(),
            head_commit: candidate.head.clone(),
            policy_hash,
            image_digest: image.clone(),
            definition_hash,
        };

        // The change, as the host sees the committed trees. Nothing has run yet.
        let gathered = gather(
            &*repo,
            ports.artifacts,
            &scope,
            &candidate.base,
            &candidate.head,
            &cfg.bounds,
            cancel,
        )
        .await?;
        let host = host::evaluate(cfg, &gathered);
        let spec = read_specification(ports.artifacts, &scope, contract).await;

        // Commands run only on a change that every host-side rule let through.
        let gates: Vec<&CommandGate> = match &definitions {
            Ok(defs) => defs
                .entries()
                .iter()
                .filter_map(|entry| match entry {
                    Resolved::Ready(gate) => Some(gate),
                    Resolved::Refused { .. } => None,
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        let io = Io {
            ports,
            scope,
            cfg,
            cancel,
            job: subject.job,
            attempt: subject.attempt,
        };
        let mut head: Option<Sandboxed> = None;
        let mut baseline: Option<Sandboxed> = None;
        if host.clean() && !gates.is_empty() {
            let mut announce = || {
                ctx.report_sandbox_ready(SandboxReady {
                    posture_verified: true,
                    tool_grants_recorded: true,
                    probe_satisfies_stage: true,
                });
            };
            head = Some(in_sandbox(&io, &candidate.head, &gates, &mut announce).await?);
            if let Some(tests) = gates.iter().find(|gate| gate.role == Role::Tests) {
                baseline = Some(in_sandbox(&io, &candidate.base, &[*tests], &mut || {}).await?);
            }
        }

        let empty_log = ports
            .artifacts
            .put(
                Vec::new(),
                MediaType::parse("text/plain").map_err(|_| StageError::Internal)?,
            )
            .await
            .map_err(|_| StageError::Tool)?;
        let asm = Assembler {
            cx: ReportContext {
                subject,
                definition: trusted,
                fidelity: fidelity(
                    ports.sandbox.fidelity(),
                    ports.workspaces.fidelity(),
                    ports.artifacts.fidelity(),
                ),
                binding: binding.digest(),
            },
            ids: ports.ids,
            clock: ports.clock,
            empty_log,
            image,
            arch: cfg.sandbox.arch.clone(),
            base: candidate.base.clone(),
        };
        let all = reports(
            &asm,
            &Findings {
                definitions: definitions.as_ref().ok(),
                host: &host,
                head: head.as_ref(),
                baseline: baseline.as_ref(),
                spec: &spec,
            },
        )
        .map_err(report_error)?;
        let violation = all.iter().any(|report| {
            report.outcome == GateOutcome::Failed
                && NONWAIVABLE.contains(&report.metadata.gate_id.as_str())
        });
        evidence_output(&binding, violation, &all)
    }

    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        let cfg = &*self.cfg;
        let ports = ctx.ports;
        let scope = TenantScope::new(ctx.identity.tenant);
        let subject = Subject {
            job: ctx.identity.job,
            stage_run: ctx.identity.stage_run,
            attempt: ctx.attempt,
            mode: ctx.mode,
        };

        // What the engine stored is read back by its hash. Nothing else is evidence.
        let stored = ctx
            .outputs
            .iter()
            .find(|output| output.name.as_str() == EVIDENCE)
            .ok_or(StageError::Blocked(BlockedCode::DependencyUnavailable))?;
        let bytes = ports
            .artifacts
            .get(&scope, &stored.artifact)
            .await
            .map_err(|_| StageError::Blocked(BlockedCode::DependencyUnavailable))?;
        let document: Value =
            serde_json::from_slice(&bytes).map_err(|_| StageError::InvalidOutput)?;
        let recorded = document
            .get("binding")
            .and_then(Binding::from_json)
            .ok_or(StageError::Blocked(BlockedCode::PolicyUnresolvable))?;
        let mut reports: Vec<GateReport> = Vec::new();
        for value in document
            .get("reports")
            .and_then(Value::as_array)
            .ok_or(StageError::InvalidOutput)?
        {
            ports
                .validator
                .validate_value(ContractKind::GateReport, 1, value)
                .map_err(|_| StageError::InvalidOutput)?;
            reports.push(
                GateReport::from_json_value(value.clone())
                    .map_err(|_| StageError::InvalidOutput)?,
            );
        }

        // The values the binding must equal, from sources the evidence cannot influence.
        let result_ref = input_artifact(ctx.contract, IMPLEMENTATION_RESULT)
            .ok_or(StageError::Blocked(BlockedCode::PolicyUnresolvable))?;
        let policy_hash = input_artifact(ctx.contract, POLICY_INPUT)
            .ok_or(StageError::Blocked(BlockedCode::PolicyUnresolvable))?
            .sha256;
        let candidate = read_candidate(ports.artifacts, &scope, &result_ref).await?;
        let repo = ports
            .workspaces
            .repo(subject.job)
            .await
            .map_err(workspace_error)?;
        let definitions = load_definitions(&*repo, cfg, &candidate.base).await?;
        let (trusted, definition_hash) = definition_of(&candidate.base, &definitions);
        let image = image_digest(cfg.sandbox.image.reference()).map_err(report_error)?;
        let expected = Binding {
            implementation_result: result_ref.sha256,
            base_commit: candidate.base.clone(),
            head_commit: candidate.head,
            policy_hash,
            image_digest: image.clone(),
            definition_hash,
        };
        let differences = recorded.differences(&expected);

        let asm = Assembler {
            cx: ReportContext {
                subject,
                definition: trusted,
                fidelity: fidelity(
                    ports.sandbox.fidelity(),
                    ports.workspaces.fidelity(),
                    ports.artifacts.fidelity(),
                ),
                binding: expected.digest(),
            },
            ids: ports.ids,
            clock: ports.clock,
            empty_log: ArtifactRef {
                sha256: Sha256Digest::of(b""),
                media_type: MediaType::parse("text/plain").map_err(|_| StageError::Internal)?,
                size_bytes: None,
            },
            image,
            arch: cfg.sandbox.arch.clone(),
            base: candidate.base,
        };
        let result = if differences.is_empty() {
            HostResult::Passed(
                "The reports are bound to this candidate commit, this policy, this image and these gate definitions."
                    .to_owned(),
            )
        } else {
            HostResult::Failed(
                differences
                    .iter()
                    .map(|field| crate::gates::scope::Violation {
                        check: binding_check(field),
                        message: format!(
                            "The evidence was made for another value of {}, so it does not count for this run.",
                            field.replace('_', " ")
                        ),
                        path: None,
                        line: None,
                    })
                    .collect(),
            )
        };
        reports.push(
            asm.host(gate_id::EVIDENCE_BINDING, result)
                .map_err(report_error)?,
        );
        let violation = !differences.is_empty()
            || document
                .get("policy_violation")
                .and_then(Value::as_bool)
                .unwrap_or(true);
        Ok(GateDecision {
            reports,
            policy_violation: violation,
            ..GateDecision::default()
        })
    }
}

fn binding_check(field: &str) -> &'static str {
    match field {
        "implementation_result" => "evidence-for-another-implementation",
        "base_commit" => "evidence-for-another-base-commit",
        "head_commit" => "evidence-for-another-commit",
        "policy_hash" => "evidence-for-another-policy",
        "image_digest" => "evidence-for-another-image",
        _ => "evidence-for-other-definitions",
    }
}

fn evidence_output(
    binding: &Binding,
    violation: bool,
    reports: &[GateReport],
) -> Result<StageOutput, StageError> {
    let listed: Result<Vec<Value>, _> = reports.iter().map(Contract::to_json_value).collect();
    let document = json!({
        "kind": "validation-evidence",
        "binding": binding.to_json(),
        "policy_violation": violation,
        "reports": listed.map_err(|_| StageError::Internal)?,
    });
    Ok(StageOutput {
        documents: vec![OutputDocument {
            name: Slug::parse(EVIDENCE).map_err(|_| StageError::Internal)?,
            contract: None,
            media_type: MediaType::parse("application/json").map_err(|_| StageError::Internal)?,
            value: document,
        }],
        ..StageOutput::default()
    })
}
