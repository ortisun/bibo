//! The `DOMAIN_DISCOVERY` stage, as Slice 1 has it: a recorded skip.
//!
//! The state machine lists the stage in Slice 1 (`requires: [SPECIFICATION]`) and says it resolves
//! the domain profile and probes the tools. Slice 1 resolves one static profile, general-software,
//! so there is no domain to discover. The handler here says so: its `applicability` returns
//! `NotApplicable` with the basis `DomainProfile`, the rule `static-general-software-profile` and
//! the plain-English reason "Slice 1 does not profile the domain". The engine then marks the run
//! `SKIPPED` and writes the rule and what it saw to the evidence ledger (`S02`,
//! `G_NOT_APPLICABLE_DECIDED`). A skipped run satisfies the stages that need it and the completion
//! of the job (ADR 0010), and it is never evidence for an assurance level.
//!
//! # What this does not do
//!
//! The stage has a second duty in the table: the tool capability probes, with a `BLOCKED` outcome
//! when a mandatory profile gate cannot run. This handler does not take it. In Slice 1 the probes
//! are taken once at start-up (`factory_composition::seams::CachedProbes`) and the router refuses
//! a stage whose runtime lacks a capability it needs, so a missing tool still stops the stage that
//! needs it. Whether that is enough is a question for the architect and is **pending**.
//!
//! # Rules this stage keeps
//!
//! * The handler never runs: `execute` and `evaluate` fail closed with an internal fault, so a
//!   run that somehow reaches an attempt does not pass by doing nothing.
//! * It holds no collaborator, so it reports fidelity `real`: the rule is deterministic.

use async_trait::async_trait;
use factory_domain::contracts::StageContract;
use factory_domain::values::{HumanText, Slug};
use factory_domain::vocabulary::{Fidelity, StageKind};

use crate::gates::framework::GateDecision;
use crate::handlers::{
    Applicability, ContractContext, GateContext, SkipBasis, SkipRule, StageContext, StageError,
    StageHandler, StageOutput,
};
use crate::stages::intake::common::{
    ContractBudget, ContractCriterion, ContractDeliverable, ContractInput, ContractSpec,
    stage_contract,
};
use crate::stages::specification::EVIDENCE;

/// The rule the skip is recorded under.
pub const SKIP_RULE: &str = "static-general-software-profile";

/// What the rule saw, in plain English. It goes in the ledger.
pub const SKIP_REASON: &str = "Slice 1 does not profile the domain. It resolves one static profile, general-software, so there is no domain to discover.";

/// The gate the contract names. The stage is skipped, so it never runs.
pub const PROFILE_GATE: &str = "domain-profile-resolved";

/// The `DOMAIN_DISCOVERY` handler of Slice 1.
#[derive(Debug, Clone, Copy, Default)]
pub struct DomainDiscoveryHandler;

impl DomainDiscoveryHandler {
    /// The handler. It needs nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StageHandler for DomainDiscoveryHandler {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn kind(&self) -> StageKind {
        StageKind::DomainDiscovery
    }

    fn applicability(&self, _ctx: &ContractContext<'_>) -> Applicability {
        match (Slug::parse(SKIP_RULE), HumanText::parse(SKIP_REASON)) {
            (Ok(rule), Ok(inputs)) => Applicability::NotApplicable(SkipRule {
                basis: SkipBasis::DomainProfile,
                rule,
                inputs,
            }),
            // Both strings are constants checked by a test. If they ever stop parsing the stage
            // must not skip silently, so it applies and then fails closed in `execute`.
            _ => Applicability::Applies,
        }
    }

    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        // The stage builds on the specification: its evidence is the input. The specification
        // always stores `evidence`; any other first output stands in only so that a test with a
        // scripted specification stage resolves, and a run with no output has no contract.
        let specification = ctx
            .upstream
            .iter()
            .find(|run| run.kind == StageKind::Specification)
            .ok_or(StageError::Internal)?;
        let evidence = specification
            .outputs
            .iter()
            .find(|output| output.name.as_str() == EVIDENCE)
            .or_else(|| specification.outputs.first())
            .ok_or(StageError::Internal)?;
        stage_contract(&ContractSpec {
            kind: StageKind::DomainDiscovery,
            job: ctx.identity.job,
            stage_run: ctx.identity.stage_run,
            mode: ctx.mode,
            created_at: ctx.now,
            contract_id: "stage-contract.domain-discovery",
            title: "Resolve the domain profile",
            purpose: "Name the domain profile the rest of the job works under.",
            problem: "Later stages apply the rules of a domain profile. Slice 1 has one static profile, general-software, so the stage records that it does not profile the domain instead of discovering one.",
            inputs: vec![ContractInput {
                name: "specification-evidence",
                description: "What the host measured while it wrote the specification.",
                sha256: evidence.artifact.sha256.clone(),
                media_type: "application/json",
                source: "previous_stage",
                produced_by: Some(specification.id),
                commit_sha: None,
                retrieved_at: ctx.now,
                trust: "trusted_internal",
            }],
            preconditions: vec![(
                "specification-passed",
                "The specification stage run passed.",
                "upstream_stage_passed",
            )],
            method: (
                "Skip by a recorded rule",
                "The profile is the same for every Slice 1 job, so a deterministic rule says the stage does not apply and the ledger records the rule.",
                "Ask a model which domain the request belongs to",
                "A model's opinion is never a reason to skip or to change a profile.",
            ),
            agent: ("domain-discovery".to_owned(), "1.0.0"),
            granted_tools: Vec::new(),
            shell: "none",
            placement: None,
            deliverables: vec![ContractDeliverable {
                name: "domain-profile",
                description: "The profile in force. Slice 1 skips the stage, so none is produced.",
                media_type: "application/json",
                required: false,
            }],
            criteria: vec![ContractCriterion {
                id: "profile-resolved",
                description: "The profile in force is the static general-software profile.",
                gate: PROFILE_GATE,
            }],
            gates: vec![PROFILE_GATE],
            budget: ContractBudget {
                wall_time_seconds: 60,
                max_tokens: 0,
                max_cost_usd: 0.0,
                attempt_timeout_seconds: 60,
                max_attempts: 1,
            },
            rollback: "Nothing is changed. The skip is recorded in the evidence ledger.",
            span_name: "stage.domain_discovery",
        })
    }

    async fn execute(&self, _ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        Err(StageError::Internal)
    }

    async fn evaluate(&self, _ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        Err(StageError::Internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rule_and_the_reason_parse_so_the_skip_is_never_silently_lost() {
        assert!(Slug::parse(SKIP_RULE).is_ok());
        assert!(HumanText::parse(SKIP_REASON).is_ok());
    }

    #[test]
    fn the_reason_says_the_plain_thing() {
        assert!(SKIP_REASON.starts_with("Slice 1 does not profile the domain."));
    }
}
