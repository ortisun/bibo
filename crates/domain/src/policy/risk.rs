//! Risk tiers (`risk_tiers` and `risk_classification` of `policies/approval.yaml`).
//!
//! The tier is **computed** from facts of the trusted diff and the specification
//! (`computed_by: policy_engine_from_trusted_diff_and_spec`). An agent's own claim is stored as a
//! claim: it can raise the tier (`agent_may_raise_tier`) and can never lower it. A change that
//! matches no criterion is `high`, not `low`: not knowing what a change is does not make it safe.
//!
//! The facts are plain booleans named like the criteria in the policy file. The engine refuses to
//! build from a policy that names a criterion this module has no fact for, so a new criterion
//! cannot be added to the file and silently never match.

use crate::vocabulary::RiskTier;

use super::approval::ApprovalPolicy;
use super::paths::DiffVerdict;
use super::{BuildError, RuleRef};

/// What is known about a change, computed by the factory and never reported by an agent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct RiskFacts {
    /// Only documentation files change.
    pub docs_only: bool,
    /// Only new test files are added.
    pub tests_only_new_files: bool,
    /// One module changes and no sensitive or protected path is touched.
    pub single_module_change_without_sensitive_or_protected_paths: bool,
    /// More than one module changes.
    pub multi_module_change: bool,
    /// A public API changes.
    pub public_api_change: bool,
    /// A schema migration that loses no data.
    pub schema_migration_without_data_loss: bool,
    /// Authentication or authorization code changes.
    pub authn_authz_change: bool,
    /// Secret handling changes.
    pub secret_handling_change: bool,
    /// A new direct dependency is added.
    pub new_dependency: bool,
    /// A sensitive file changes.
    pub sensitive_file_change: bool,
    /// A data migration.
    pub data_migration: bool,
    /// Concurrency or locking code changes.
    pub concurrency_or_locking_change: bool,
    /// Infrastructure changes.
    pub infra_change: bool,
    /// A protected path changes (through the exception flow).
    pub protected_path_change: bool,
    /// The policy or the sandbox changes.
    pub policy_or_sandbox_change: bool,
    /// Money moves.
    pub money_movement: bool,
    /// Something physical is actuated.
    pub physical_actuation: bool,
    /// A regulated workflow.
    pub regulated_workflow: bool,
    /// Production data is accessed.
    pub production_data_access: bool,
}

impl RiskFacts {
    fn holds(&self, criterion: &str) -> Option<bool> {
        Some(match criterion {
            "docs_only" => self.docs_only,
            "tests_only_new_files" => self.tests_only_new_files,
            "single_module_change_without_sensitive_or_protected_paths" => {
                self.single_module_change_without_sensitive_or_protected_paths
            }
            "multi_module_change" => self.multi_module_change,
            "public_api_change" => self.public_api_change,
            "schema_migration_without_data_loss" => self.schema_migration_without_data_loss,
            "authn_authz_change" => self.authn_authz_change,
            "secret_handling_change" => self.secret_handling_change,
            "new_dependency" => self.new_dependency,
            "sensitive_file_change" => self.sensitive_file_change,
            "data_migration" => self.data_migration,
            "concurrency_or_locking_change" => self.concurrency_or_locking_change,
            "infra_change" => self.infra_change,
            "protected_path_change" => self.protected_path_change,
            "policy_or_sandbox_change" => self.policy_or_sandbox_change,
            "money_movement" => self.money_movement,
            "physical_actuation" => self.physical_actuation,
            "regulated_workflow" => self.regulated_workflow,
            "production_data_access" => self.production_data_access,
            _ => return None,
        })
    }

    /// Sets the facts that the path rules know: a sensitive file was touched, a protected path
    /// was changed. A blocked diff counts as a protected-path change.
    #[must_use]
    pub fn with_diff(mut self, diff: &DiffVerdict) -> Self {
        match diff {
            DiffVerdict::Allowed {
                sensitive,
                exception_for,
            } => {
                self.sensitive_file_change |= !sensitive.is_empty();
                self.protected_path_change |= !exception_for.is_empty();
            }
            DiffVerdict::Blocked { .. } => self.protected_path_change = true,
        }
        self
    }
}

/// The tier of a change and what it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskAssessment {
    /// The tier that applies.
    pub tier: RiskTier,
    /// The tier the policy computed from the facts alone.
    pub computed: RiskTier,
    /// The criteria that held, as the policy file spells them.
    pub matched: Vec<String>,
    /// No criterion held, so the tier is `high` by default.
    pub unclassified: bool,
    /// The agent's claim, kept as a claim. It never lowered anything.
    pub agent_claim: Option<RiskTier>,
    /// The reviews the tier requires.
    pub required_reviews: Vec<String>,
    /// The approvals the tier requires.
    pub required_approvals: u32,
    /// The rule.
    pub rule: RuleRef,
}

#[derive(Debug)]
struct Tier {
    id: RiskTier,
    criteria: Vec<String>,
    reviews: Vec<String>,
    approvals: u32,
}

/// The risk rules of one approval policy.
#[derive(Debug)]
pub struct RiskPolicy {
    tiers: Vec<Tier>,
    may_raise: bool,
}

impl RiskPolicy {
    /// Reads the risk rules.
    ///
    /// # Errors
    /// A [`BuildError`] when a criterion has no fact here, when a tier is missing, or when the
    /// policy lets an agent lower its own tier.
    pub fn from_policy(policy: &ApprovalPolicy) -> Result<Self, BuildError> {
        if policy.risk_classification.agent_may_lower_tier {
            return Err(BuildError::ProtectionDisabled {
                key: "risk_classification.agent_may_lower_tier",
                found: "true".to_owned(),
            });
        }
        let known = RiskFacts::default();
        let mut tiers = Vec::new();
        for t in &policy.risk_tiers {
            for criterion in &t.criteria_any {
                if known.holds(criterion).is_none() {
                    return Err(BuildError::UnknownValue {
                        key: "risk_tiers.criteria_any",
                        found: criterion.clone(),
                    });
                }
            }
            tiers.push(Tier {
                id: t.id,
                criteria: t.criteria_any.clone(),
                reviews: t.required_reviews.clone(),
                approvals: t.required_approvals,
            });
        }
        for tier in [
            RiskTier::Low,
            RiskTier::Medium,
            RiskTier::High,
            RiskTier::Critical,
        ] {
            if !tiers.iter().any(|t| t.id == tier) {
                return Err(BuildError::Contradiction(format!(
                    "risk_tiers has no {}",
                    tier.as_str()
                )));
            }
        }
        Ok(Self {
            tiers,
            may_raise: policy.risk_classification.agent_may_raise_tier,
        })
    }

    fn tier(&self, id: RiskTier) -> Option<&Tier> {
        self.tiers.iter().find(|t| t.id == id)
    }

    /// Computes the tier of a change. `agent_claim` is what the agent said; it can raise the tier
    /// and never lowers it.
    #[must_use]
    pub fn assess(&self, facts: &RiskFacts, agent_claim: Option<RiskTier>) -> RiskAssessment {
        let mut matched = Vec::new();
        let mut computed: Option<RiskTier> = None;
        for tier in &self.tiers {
            for criterion in &tier.criteria {
                if facts.holds(criterion) == Some(true) {
                    matched.push(criterion.clone());
                    computed = Some(computed.map_or(tier.id, |c| c.max(tier.id)));
                }
            }
        }
        let unclassified = computed.is_none();
        let computed = computed.unwrap_or(RiskTier::High);
        let tier = match agent_claim {
            Some(claim) if self.may_raise => computed.max(claim),
            _ => computed,
        };
        let (required_reviews, required_approvals) = self.tier(tier).map_or_else(
            || (Vec::new(), u32::MAX),
            |t| (t.reviews.clone(), t.approvals),
        );
        RiskAssessment {
            tier,
            computed,
            matched,
            unclassified,
            agent_claim,
            required_reviews,
            required_approvals,
            rule: RuleRef::new("risk_tiers", tier.as_str()),
        }
    }
}
