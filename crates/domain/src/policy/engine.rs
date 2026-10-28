//! The engine: every evaluator built from one pair of policy documents.

use super::BuildError;
use super::approval::ApprovalPolicy;
use super::authority::AuthorityPolicy;
use super::budget::BudgetPolicy;
use super::commands::CommandPolicy;
use super::dependency::DependencyPolicy;
use super::egress::EgressPolicy;
use super::paths::PathPolicy;
use super::risk::RiskPolicy;
use super::security::SecurityPolicy;
use super::tools::ToolPolicy;

/// The actions the other evaluators depend on. Each must need a human whatever the level: the
/// protected-path exception, a new direct dependency and the waiver of a gate.
const ALWAYS_HUMAN_ACTIONS: [&str; 3] = [
    "change_protected_path",
    "add_new_direct_dependency",
    "waive_failed_gate",
];

/// All the pure evaluators for one pair of policies. Building it is the check that the pair is
/// something the engine can honour: it fails, and no evaluator exists, when a document turns off a
/// protection the engine always applies or contradicts itself.
#[derive(Debug)]
pub struct PolicyEngine {
    /// Paths, diffs and symbolic links.
    pub paths: PathPolicy,
    /// Argument vectors.
    pub commands: CommandPolicy,
    /// Tool grants and skills.
    pub tools: ToolPolicy,
    /// Hosts, ports and resolved addresses.
    pub egress: EgressPolicy,
    /// New direct dependencies.
    pub dependency: DependencyPolicy,
    /// Allowlist, autonomy ladder, actions, overrides and admission.
    pub authority: AuthorityPolicy,
    /// Risk tiers.
    pub risk: RiskPolicy,
    /// Ceilings and caps.
    pub budget: BudgetPolicy,
}

impl PolicyEngine {
    /// Builds the evaluators.
    ///
    /// # Errors
    /// The first [`BuildError`] any evaluator reports.
    pub fn new(security: &SecurityPolicy, approval: &ApprovalPolicy) -> Result<Self, BuildError> {
        let authority = AuthorityPolicy::from_policies(approval, security)?;
        for action in ALWAYS_HUMAN_ACTIONS {
            if !authority.always_needs_human(action) {
                return Err(BuildError::Contradiction(format!(
                    "the action {action} must need a human at every level, because the path, dependency and override rules rely on it"
                )));
            }
        }
        Ok(Self {
            paths: PathPolicy::from_policy(security)?,
            commands: CommandPolicy::from_policy(security)?,
            tools: ToolPolicy::from_policy(security)?,
            egress: EgressPolicy::from_policy(security)?,
            dependency: DependencyPolicy::from_policy(security)?,
            authority,
            risk: RiskPolicy::from_policy(approval)?,
            budget: BudgetPolicy::from_policy(security)?,
        })
    }
}
