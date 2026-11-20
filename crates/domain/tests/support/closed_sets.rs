//! Every closed set (Rust enum with exact wire names) that a contract schema uses.
//!
//! `contract_examples.rs` compares this list with the `enum` keywords in the schema files in both
//! directions. Adding an enum to a contract without listing it here makes that test fail, and so
//! does listing one that no schema defines.

use factory_domain::contracts::agent_manifest::{
    AgentPlacement, RecommendedTier, SecretsMode, ToolAccess,
};
use factory_domain::contracts::common::{NetworkMode, ShellMode};
use factory_domain::contracts::domain_capability_profile::ProfileStatus;
use factory_domain::contracts::domain_event::AggregateKind;
use factory_domain::contracts::evidence_ledger_entry::{ClaimKind, TestResult};
use factory_domain::contracts::evidence_manifest::{
    AdapterKind, DeliveredGateOutcome, RequiredApproval,
};
use factory_domain::contracts::gate_report::{
    BaselineDelta, BlockedCode, DefinitionSource, ExecutorKind, NotApplicableCode,
    NotApplicableDecider, SandboxNetwork,
};
use factory_domain::contracts::project_manifest::{ReadabilityRule, TestReportFormat};
use factory_domain::contracts::review_verdict::{
    Category, DefectClass, NextAction, ReproductionKind, Severity,
};
use factory_domain::contracts::specification_contract::{
    ApprovalBasis, ConstraintKind, Level, Priority, QuestionStatus, RevisionMethod,
    SpecApproverRole, SpecArtifactRole, SpecStatus, SpecToolSkill,
};
use factory_domain::contracts::stage_contract::{
    AssumptionStatus, EscalationTarget, EscalationTrigger, EvaluatorKind, HiddenInput, InputSource,
    Jitter, Placement, PreconditionCheck, RetryClass, SideEffects, Trust, VerificationKind,
};
use factory_domain::contracts::task_dag::{ChangeKind, ModelTier, RequiredEvidence, TaskKind};
use factory_domain::vocabulary::{
    AssuranceLevel, ConfidenceLevel, ExecutionMode, Fidelity, GateOutcome, HumanRole,
    RecorderFidelity, ReviewerRole, RiskTier, StageKind, Verdict,
};

macro_rules! sets {
    ($($ty:ty),+ $(,)?) => {
        vec![ $( <$ty>::ALL.iter().map(|value| value.as_str()).collect::<Vec<&'static str>>() ),+ ]
    };
}

/// The names of every enum that a contract uses.
pub fn all() -> Vec<Vec<&'static str>> {
    sets![
        // shared vocabulary
        ExecutionMode,
        Fidelity,
        RecorderFidelity,
        HumanRole,
        RiskTier,
        ConfidenceLevel,
        GateOutcome,
        Verdict,
        ReviewerRole,
        StageKind,
        AssuranceLevel,
        // common
        NetworkMode,
        ShellMode,
        // evidence ledger entry
        ClaimKind,
        TestResult,
        // stage contract
        InputSource,
        Trust,
        PreconditionCheck,
        Placement,
        VerificationKind,
        EvaluatorKind,
        HiddenInput,
        AssumptionStatus,
        Jitter,
        RetryClass,
        SideEffects,
        EscalationTarget,
        EscalationTrigger,
        // specification contract
        SpecStatus,
        SpecApproverRole,
        ApprovalBasis,
        Priority,
        Level,
        QuestionStatus,
        ConstraintKind,
        SpecToolSkill,
        SpecArtifactRole,
        RevisionMethod,
        // task dag
        TaskKind,
        ChangeKind,
        ModelTier,
        RequiredEvidence,
        // gate report
        DefinitionSource,
        ExecutorKind,
        SandboxNetwork,
        BlockedCode,
        NotApplicableCode,
        NotApplicableDecider,
        BaselineDelta,
        // project manifest
        ReadabilityRule,
        TestReportFormat,
        // review verdict
        Severity,
        Category,
        ReproductionKind,
        NextAction,
        DefectClass,
        // agent manifest
        ToolAccess,
        SecretsMode,
        AgentPlacement,
        RecommendedTier,
        // domain capability profile
        ProfileStatus,
        // domain event
        AggregateKind,
        // evidence manifest
        DeliveredGateOutcome,
        AdapterKind,
        RequiredApproval,
    ]
}
