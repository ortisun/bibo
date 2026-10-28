//! The approval stage handler: a human gate.
//!
//! `execute` reads the delivery back, checks that the pull request is still the draft at the
//! commit that was delivered and that the evidence still describes the world, and stores the
//! **approval request**: the binding the person is shown and the facts the policy needs to say who
//! may approve. `evaluate` hands the engine one gate report about the evidence and says that the
//! gate is a human gate. The person's decision does not come through the handler: it comes
//! through [`ApprovalService`](super::service::ApprovalService), which records it and asks the
//! engine to move the stage run.
//!
//! A stage run whose evidence is not clear (a gate failed, or was blocked and nobody decided about
//! it) is not put in front of a person: the gate report is `FAILED`, the engine resolves the gate
//! as failed, and there is no stage run in the waiting state for an approval to move.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::{Contract, GateReport, StageContract};
use factory_domain::ids::GateReportId;
use factory_domain::policy::PolicyEngine;
use factory_domain::scope::TenantScope;
use factory_domain::values::{GitSha, MediaType};
use factory_domain::vocabulary::{Fidelity, GateOutcome, StageKind};
use factory_ports::githost::{ChangeHost, GitScope, PullRequestLifecycle, PullRequestRef};
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use serde_json::Value;

use super::contract::{GATE, REQUEST, resolve};
use super::request::{ApprovalRequest, TRANSLATION_WARNING};
use super::seams::ApprovalSources;
use crate::gates::framework::GateDecision;
use crate::handlers::{
    ContractContext, GateContext, OutputDocument, StageContext, StageError, StageHandler,
    StageOutput,
};
use crate::stages::delivery::binding::{self, Now};
use crate::stages::delivery::contract::RESULT as DELIVERY_RESULT;
use crate::stages::delivery::handler::{fidelity_of, host_error, seam_error, slug};
use crate::stages::delivery::input::{
    DOCUMENTATION_GATE, POLICY_INPUT, VALIDATION_EVIDENCE, contract_input,
};
use crate::stages::delivery::{DeliverySources, EvidenceDrift};
use crate::stages::intake::common::{
    Executor, GateDefinition, GateFacts, GateSubject, gate_report,
};
use crate::stages::validation::Binding;

const GATE_TEXT: &str = "approval-evidence-clear 1.0.0: every gate in the evidence passed or does not apply, or was blocked and then decided by a person, and the pull request is still the open draft that was delivered.";

/// What the approval stage is built from by the composition root.
#[derive(Clone)]
pub struct ApprovalConfig {
    /// The policy engine: the risk tier is computed here.
    pub policy: Arc<PolicyEngine>,
    /// The commit of the factory's own gate definitions, recorded in the gate report.
    pub definition_commit: GitSha,
}

impl std::fmt::Debug for ApprovalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalConfig { .. }")
    }
}

/// The ports and seams the approval stage uses besides the engine's.
#[derive(Clone)]
pub struct ApprovalHandlerDeps {
    /// Reads the pull request and the base branch.
    pub host: Arc<dyn ChangeHost>,
    /// Ledger, tree and bound values.
    pub delivery: Arc<dyn DeliverySources>,
    /// The requester.
    pub approvals: Arc<dyn ApprovalSources>,
    /// Tells the engine that a bound value changed.
    pub drift: Arc<dyn EvidenceDrift>,
}

/// The approval stage.
#[derive(Clone)]
pub struct ApprovalHandler {
    config: Arc<ApprovalConfig>,
    deps: ApprovalHandlerDeps,
}

impl std::fmt::Debug for ApprovalHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalHandler { .. }")
    }
}

impl ApprovalHandler {
    /// A handler built from the composition root's configuration.
    #[must_use]
    pub fn new(config: Arc<ApprovalConfig>, deps: ApprovalHandlerDeps) -> Self {
        Self { config, deps }
    }
}

fn text_of<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// Open warnings of the translation rule in a gate report.
fn translation_warnings(report: &GateReport) -> u32 {
    let count = report
        .warnings
        .iter()
        .flatten()
        .filter(|warning| warning.check_id.as_str() == TRANSLATION_WARNING)
        .count();
    u32::try_from(count).unwrap_or(u32::MAX)
}

#[async_trait]
impl StageHandler for ApprovalHandler {
    fn fidelity(&self) -> Fidelity {
        fidelity_of(&[
            self.deps.host.fidelity(),
            self.deps.delivery.fidelity(),
            self.deps.approvals.fidelity(),
        ])
    }

    fn kind(&self) -> StageKind {
        StageKind::Approval
    }

    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        resolve(ctx)
    }

    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        let ports = ctx.ports;
        let identity = ctx.identity;
        let scope = TenantScope::new(identity.tenant);
        let unavailable = || StageError::Blocked(BlockedCode::DependencyUnavailable);
        let read = |name: &'static str| {
            let reference = contract_input(ctx.contract, name);
            async move {
                let reference = reference.ok_or_else(unavailable)?;
                let bytes = ports
                    .artifacts
                    .get(&scope, &reference)
                    .await
                    .map_err(|_| unavailable())?;
                serde_json::from_slice::<Value>(&bytes).map_err(|_| StageError::InvalidOutput)
            }
        };
        let delivery = read(DELIVERY_RESULT).await?;
        let evidence = read(VALIDATION_EVIDENCE).await?;
        let documentation = read(DOCUMENTATION_GATE).await?;
        let policy_hash = contract_input(ctx.contract, POLICY_INPUT)
            .ok_or(StageError::Blocked(BlockedCode::PolicyUnresolvable))?
            .sha256;

        if delivery.get("delivered").and_then(Value::as_bool) != Some(true) {
            return Err(StageError::PolicyDenied);
        }
        let repository = text_of(&delivery, "repository").ok_or(StageError::InvalidOutput)?;
        let number = delivery
            .get("pull_request")
            .and_then(Value::as_u64)
            .ok_or(StageError::InvalidOutput)?;
        let parse_sha = |key: &str| {
            text_of(&delivery, key)
                .and_then(|text| GitSha::parse(text).ok())
                .ok_or(StageError::InvalidOutput)
        };
        let (pr_head, tree, base) = (
            parse_sha("head_commit")?,
            parse_sha("tree")?,
            parse_sha("base_commit")?,
        );
        let head_commit =
            CommitSha::parse(pr_head.as_str()).map_err(|_| StageError::InvalidOutput)?;
        let base_commit = CommitSha::parse(base.as_str()).map_err(|_| StageError::InvalidOutput)?;
        let repo = RepoRef::parse(repository).map_err(|_| StageError::InvalidOutput)?;
        let head_branch =
            BranchName::new(text_of(&delivery, "head_branch").ok_or(StageError::InvalidOutput)?)
                .map_err(|_| StageError::InvalidOutput)?;
        let base_branch =
            BranchName::new(text_of(&delivery, "base_branch").ok_or(StageError::InvalidOutput)?)
                .map_err(|_| StageError::InvalidOutput)?;
        let manifest = factory_domain::values::Sha256Digest::parse(
            text_of(&delivery, "manifest_sha256").ok_or(StageError::InvalidOutput)?,
        )
        .map_err(|_| StageError::InvalidOutput)?;
        let spec_version = delivery
            .get("spec_version")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(StageError::InvalidOutput)?;

        // The pull request must still be the open draft at the delivered commit.
        let git = GitScope {
            tenant: identity.tenant,
            job: identity.job,
            stage: StageKind::Approval,
            repo: repo.clone(),
        };
        let state = self
            .deps
            .host
            .pull_request_state(&git, &PullRequestRef { repo, number })
            .await
            .map_err(|e| host_error(&e))?;
        if state.lifecycle != PullRequestLifecycle::Open
            || !state.draft
            || state.head != head_branch
            || state.head_sha != head_commit
        {
            return Err(StageError::PolicyDenied);
        }

        // The evidence must still describe the world (checked again when an approval is recorded).
        let binding = evidence
            .get("binding")
            .and_then(Binding::from_json)
            .ok_or(StageError::InvalidOutput)?;
        let live_base = self
            .deps
            .host
            .resolve_branch(&git, &base_branch)
            .await
            .map_err(|e| host_error(&e))?;
        let current = self
            .deps
            .delivery
            .current_values(&identity, &base_commit)
            .await
            .map_err(seam_error)?;
        let differences = binding::differences(
            &binding,
            &Now {
                live_base: &live_base,
                current: &current,
                policy_hash: &policy_hash,
                head: &head_commit,
                implementation_sha256: &binding.implementation_result,
            },
        )
        .ok_or(StageError::Internal)?;
        if !differences.is_empty() {
            if binding::is_drift(&differences) {
                self.deps
                    .drift
                    .binding_changed(identity.tenant, identity.job)
                    .await
                    .map_err(seam_error)?;
                return Err(StageError::Cancelled);
            }
            return Err(StageError::PolicyDenied);
        }

        // Gates and warnings, from the stored reports.
        let ledger = self
            .deps
            .delivery
            .ledger(&identity)
            .await
            .map_err(seam_error)?;
        let reports: Vec<GateReport> = evidence
            .get("reports")
            .and_then(Value::as_array)
            .ok_or(StageError::InvalidOutput)?
            .iter()
            .map(|value| {
                GateReport::from_json_value(value.clone()).map_err(|_| StageError::InvalidOutput)
            })
            .collect::<Result<_, _>>()?;
        let decided = |gate: &factory_domain::values::Slug| {
            ledger.dispositions.iter().any(|(held, _)| held == gate)
        };
        let gates_clear = !reports.is_empty()
            && reports.iter().all(|report| match report.outcome {
                GateOutcome::Passed | GateOutcome::NotApplicable => true,
                GateOutcome::Blocked => decided(&report.metadata.gate_id),
                GateOutcome::Failed => false,
            });
        let documentation_report =
            GateReport::from_json_value(documentation).map_err(|_| StageError::InvalidOutput)?;
        let open_translation_warnings = reports
            .iter()
            .chain(std::iter::once(&documentation_report))
            .map(translation_warnings)
            .fold(0u32, u32::saturating_add);

        // The facts the policy reads to say who may approve.
        let target = self
            .deps
            .delivery
            .target(&identity)
            .await
            .map_err(seam_error)?;
        let risk = self.config.policy.risk.assess(&target.risk, None);
        let requester = self
            .deps
            .approvals
            .requester(&identity)
            .await
            .map_err(seam_error)?;

        let request = ApprovalRequest {
            repository: repository.to_owned(),
            pull_request: number,
            head_branch: head_branch.as_str().to_owned(),
            base_branch: base_branch.as_str().to_owned(),
            pr_head,
            tree,
            base,
            manifest,
            spec_version,
            gates_clear,
            open_translation_warnings,
            tier: risk.tier,
            protected_path_change: target.risk.protected_path_change,
            sensitive_file_change: target.risk.sensitive_file_change,
            new_dependency: target.risk.new_dependency,
            requester,
            evidence_binding: binding,
            created_at: ports.clock.now(),
        };
        Ok(StageOutput {
            documents: vec![OutputDocument {
                name: slug(REQUEST)?,
                contract: None,
                media_type: MediaType::parse("application/json")
                    .map_err(|_| StageError::Internal)?,
                value: request.to_json(),
            }],
            ..StageOutput::default()
        })
    }

    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        let ports = ctx.ports;
        let scope = TenantScope::new(ctx.identity.tenant);
        let stored = ctx
            .outputs
            .iter()
            .find(|output| output.name.as_str() == REQUEST)
            .ok_or(StageError::InvalidOutput)?;
        let bytes = ports
            .artifacts
            .get(&scope, &stored.artifact)
            .await
            .map_err(|_| StageError::Blocked(BlockedCode::DependencyUnavailable))?;
        let request = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .as_ref()
            .and_then(ApprovalRequest::from_json)
            .ok_or(StageError::InvalidOutput)?;
        let fidelity = match self.fidelity() {
            Fidelity::Real => "real",
            Fidelity::Fake => "fake",
        };
        let now = ports.clock.now();
        let failures = if request.gates_clear {
            Vec::new()
        } else {
            vec![(
                "gates-not-clear".to_owned(),
                "A gate in the evidence failed, or was blocked and no person decided about it, so there is nothing to approve."
                    .to_owned(),
            )]
        };
        let report = gate_report(
            &GateSubject {
                job: ctx.identity.job,
                stage_run: ctx.identity.stage_run,
                attempt: ctx.attempt,
                mode: ctx.mode,
                report_id: GateReportId::from_uuid(ports.ids.new_uuid()),
                started_at: now,
                finished_at: ports.clock.now(),
            },
            &GateFacts {
                definition: GateDefinition {
                    id: GATE,
                    version: "1.0.0",
                    text: GATE_TEXT,
                    commit: self.config.definition_commit.clone(),
                },
                outcome: if failures.is_empty() {
                    "PASSED"
                } else {
                    "FAILED"
                },
                title: "Evidence to approve".to_owned(),
                reason: if failures.is_empty() {
                    "Every gate in the evidence is clear, and the pull request is the open draft that was delivered."
                        .to_owned()
                } else {
                    "The evidence is not clear.".to_owned()
                },
                failures,
                blocked: None,
                fidelity,
                executor: Executor::InProcess,
                commands: Vec::new(),
                tools: vec![("factory-approval".to_owned(), "1.0.0".to_owned())],
                evidence: vec![
                    format!("manifest={}", request.manifest.as_str()),
                    format!("head={}", request.pr_head.as_str()),
                    format!("gates_clear={}", request.gates_clear),
                ],
            },
        )?;
        Ok(GateDecision {
            reports: vec![report],
            human_gate: true,
            ..GateDecision::default()
        })
    }
}
