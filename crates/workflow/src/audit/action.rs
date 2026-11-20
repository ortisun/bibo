//! The kinds of audit event the policy requires (`policies/security.yaml`, `audit.must_record`).
//!
//! The audit log of the `Store` port records the actor, the action, the policy hash, the
//! correlation id and the time. It has no field for the decision, so the action carries it as a
//! suffix after a dot: `gate_result.passed`, `authorization_decision.denied`. The part before the
//! first dot is the required type, and the verifier (`crate::audit::verifier`) and the coverage
//! test read only that part.

use factory_domain::error::ValueError;
use factory_domain::values::Slug;

/// One of the audit event types the policy requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AuditKind {
    /// A webhook was accepted or rejected. Recorded by the API, not by the engine.
    WebhookAcceptedOrRejected,
    /// A person or a rule was allowed or denied an action: admission, a human decision.
    AuthorizationDecision,
    /// The tools that policy granted to a stage run.
    ToolGrantIssued,
    /// A tool call that policy refused.
    ToolCallDenied,
    /// A command that the factory itself ran.
    CommandExecuted,
    /// A sandbox was created, passed or failed its posture check, and was destroyed.
    SandboxCreatedPostureResultDestroyed,
    /// A request through the egress proxy.
    EgressRequest,
    /// A secret was redacted or blocked.
    SecretRedactedOrBlocked,
    /// A protected-path decision of the scope check.
    ProtectedPathDecision,
    /// The result of a gate.
    GateResult,
    /// An approval was granted or rejected.
    ApprovalGrantedOrRejected,
    /// A person overrode a block.
    HumanOverride,
    /// A job token was minted or revoked.
    CredentialMintedAndRevoked,
    /// A budget threshold was crossed.
    BudgetThresholdCrossed,
}

impl AuditKind {
    /// Every required type, in the order of the policy file.
    pub const ALL: [AuditKind; 14] = [
        Self::WebhookAcceptedOrRejected,
        Self::AuthorizationDecision,
        Self::ToolGrantIssued,
        Self::ToolCallDenied,
        Self::CommandExecuted,
        Self::SandboxCreatedPostureResultDestroyed,
        Self::EgressRequest,
        Self::SecretRedactedOrBlocked,
        Self::ProtectedPathDecision,
        Self::GateResult,
        Self::ApprovalGrantedOrRejected,
        Self::HumanOverride,
        Self::CredentialMintedAndRevoked,
        Self::BudgetThresholdCrossed,
    ];

    /// The type as the policy file spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WebhookAcceptedOrRejected => "webhook_accepted_or_rejected",
            Self::AuthorizationDecision => "authorization_decision",
            Self::ToolGrantIssued => "tool_grant_issued",
            Self::ToolCallDenied => "tool_call_denied",
            Self::CommandExecuted => "command_executed",
            Self::SandboxCreatedPostureResultDestroyed => {
                "sandbox_created_posture_result_destroyed"
            }
            Self::EgressRequest => "egress_request",
            Self::SecretRedactedOrBlocked => "secret_redacted_or_blocked",
            Self::ProtectedPathDecision => "protected_path_decision",
            Self::GateResult => "gate_result",
            Self::ApprovalGrantedOrRejected => "approval_granted_or_rejected",
            Self::HumanOverride => "human_override",
            Self::CredentialMintedAndRevoked => "credential_minted_and_revoked",
            Self::BudgetThresholdCrossed => "budget_threshold_crossed",
        }
    }

    /// The type that an action slug starts with, or `None` for an action of another family.
    #[must_use]
    pub fn of_action(action: &str) -> Option<Self> {
        let head = action.split('.').next().unwrap_or(action);
        Self::ALL.iter().copied().find(|kind| kind.as_str() == head)
    }

    /// True when the engine records this type itself. The others are recorded by the component
    /// that sees the event (the API, the egress proxy, the redactor, the stage handlers), through
    /// `StageContext::note_audit` for a handler.
    #[must_use]
    pub const fn recorded_by_engine(self) -> bool {
        matches!(
            self,
            Self::AuthorizationDecision
                | Self::ToolGrantIssued
                | Self::GateResult
                | Self::ApprovalGrantedOrRejected
                | Self::HumanOverride
                | Self::CredentialMintedAndRevoked
                | Self::BudgetThresholdCrossed
        )
    }
}

/// The decision part of an audit action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditDecision {
    /// The action was allowed, granted, minted or passed.
    Granted,
    /// The action was refused or denied.
    Denied,
    /// The action ended something: revoked, destroyed, rejected.
    Ended,
    /// A fact was noted and no decision was involved.
    Noted,
}

impl AuditDecision {
    const fn suffix(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Denied => "denied",
            Self::Ended => "ended",
            Self::Noted => "noted",
        }
    }
}

/// An audit action: a required type and the decision, ready to store as a slug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditAction {
    /// The required type.
    pub kind: AuditKind,
    /// The decision.
    pub decision: AuditDecision,
}

impl AuditAction {
    /// An action of `kind` with `decision`.
    #[must_use]
    pub const fn new(kind: AuditKind, decision: AuditDecision) -> Self {
        Self { kind, decision }
    }

    /// The slug stored in the audit log, such as `gate_result.granted`.
    ///
    /// # Errors
    /// Never in practice: every type and suffix is a valid slug. The error is returned so the
    /// caller does not need a panic path.
    pub fn slug(self) -> Result<Slug, ValueError> {
        Slug::parse(&format!(
            "{}.{}",
            self.kind.as_str(),
            self.decision.suffix()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_type_and_decision_makes_a_valid_slug() {
        for kind in AuditKind::ALL {
            for decision in [
                AuditDecision::Granted,
                AuditDecision::Denied,
                AuditDecision::Ended,
                AuditDecision::Noted,
            ] {
                let slug = AuditAction::new(kind, decision).slug().expect("a slug");
                assert_eq!(AuditKind::of_action(slug.as_str()), Some(kind));
            }
        }
    }

    #[test]
    fn an_action_of_another_family_has_no_required_type() {
        assert_eq!(AuditKind::of_action("job.cancelled"), None);
        assert_eq!(AuditKind::of_action("gate_resultx.granted"), None);
    }

    #[test]
    fn the_engine_records_the_types_it_can_see() {
        assert!(AuditKind::GateResult.recorded_by_engine());
        assert!(AuditKind::CredentialMintedAndRevoked.recorded_by_engine());
        assert!(!AuditKind::WebhookAcceptedOrRejected.recorded_by_engine());
        assert!(!AuditKind::EgressRequest.recorded_by_engine());
    }
}
