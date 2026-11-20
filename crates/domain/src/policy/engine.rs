//! The engine: every evaluator built from one pair of policy documents.

use super::BuildError;
use super::approval::ApprovalPolicy;
use super::authority::AuthorityPolicy;
use super::budget::BudgetPolicy;
use super::commands::CommandPolicy;
use super::decision::Designation;
use super::dependency::DependencyPolicy;
use super::egress::EgressPolicy;
use super::paths::PathPolicy;
use super::risk::RiskPolicy;
use super::security::SecurityPolicy;
use super::tools::ToolPolicy;

/// The actions the other evaluators depend on. Each must need a human whatever the level: the
/// protected-path exception, a new direct dependency, the build code of a new package and the
/// waiver of a gate.
const ALWAYS_HUMAN_ACTIONS: [&str; 4] = [
    "change_protected_path",
    "add_new_direct_dependency",
    "approve_build_code",
    "waive_failed_gate",
];

/// The actions only a security approver may decide, and nobody else, whatever else the row says.
/// Build code runs on the machines that build the project; the dependency gate asks the engine
/// who may approve it and relies on this answer.
const SECURITY_APPROVER_ONLY_ACTIONS: [&str; 1] = ["approve_build_code"];

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
        for action in SECURITY_APPROVER_ONLY_ACTIONS {
            if authority.approver_designations(action) != [Designation::SecurityApprover] {
                return Err(BuildError::Contradiction(format!(
                    "the action {action} must name the security approver and no other designation as its approver, because the dependency gate relies on it"
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
