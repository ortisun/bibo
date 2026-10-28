//! `policies/approval.yaml` as typed values: autonomy levels, who may decide, risk tiers, the
//! action table and the commands that carry a decision.
//!
//! Same rules as `security.rs`: every struct rejects unknown keys, and a field the file may leave
//! out is an `Option`. The pure evaluation (who may approve what at which level) belongs to
//! `s1-policy-evaluation`.

use std::collections::BTreeMap;

use crate::vocabulary::RiskTier;

use super::common::{
    ConfigSource, ConflictResolution, PolicyStatus, ProjectOverrides, SchemaVersionOne, ThreatId,
    closed_set, strict,
};

strict! {
    /// The whole of `policies/approval.yaml`.
    pub struct ApprovalPolicy {
        /// Always 1.
        pub schema_version: SchemaVersionOne,
        /// Identity and global rules.
        pub policy: ApprovalHeader,
        /// Autonomy levels.
        pub autonomy: Autonomy,
        /// Where roles come from.
        pub authority: Authority,
        /// The roles.
        pub roles: Vec<Role>,
        /// Separation of duties.
        pub separation_of_duties: SeparationOfDuties,
        /// Risk tiers.
        pub risk_tiers: Vec<RiskTierRule>,
        /// How risk is classified.
        pub risk_classification: RiskClassification,
        /// The action table.
        pub actions: Vec<ActionRule>,
        /// Actions that always need a human.
        pub always_human: Vec<String>,
        /// Actions that are never allowed through the factory.
        pub never_allowed_even_with_human_via_the_factory: Vec<String>,
        /// What an approval is bound to.
        pub approval_binding: ApprovalBinding,
        /// The commands.
        pub commands: Commands,
        /// Intake authorization.
        pub intake: Intake,
    }
}

closed_set! {
    /// What a request with no row in the action table gets. The only value is a human decision.
    pub enum HumanByDefault {
        /// A person decides.
        RequireHuman,
    }
}

strict! {
    /// Identity and global rules of the approval policy.
    pub struct ApprovalHeader {
        /// Always `approval`.
        pub id: String,
        /// The policy version.
        pub version: u32,
        /// Designed or enforced.
        pub status: PolicyStatus,
        /// What an action with no row gets. Required, and only `require_human` is valid.
        pub default_action: HumanByDefault,
        /// How rules combine.
        pub conflict_resolution: ConflictResolution,
        /// What a project policy may do.
        pub project_overrides: ProjectOverrides,
        /// Where the file must be read from.
        pub config_source: ConfigSource,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// One autonomy level.
    pub struct AutonomyLevel {
        /// The level, such as `L1`.
        pub id: String,
        /// Its name.
        pub name: String,
        /// What it allows.
        pub description: String,
        /// The GitHub writes it allows.
        pub github_writes: Vec<String>,
        /// What still needs a human.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub human_required_for: Option<Vec<String>>,
        /// What must hold before the level applies to a pull request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preconditions: Option<Vec<String>>,
        /// False for a level that is off.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        /// What opting in needs.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub opt_in_requires: Option<Vec<String>>,
        /// Every condition an automatic merge needs.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub eligibility_all_of: Option<Vec<String>>,
        /// What revokes the level automatically.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoke_automatically_on: Option<Vec<String>>,
    }
}

strict! {
    /// Deployment rules.
    pub struct Deploy {
        /// Whether deployment is on. Must be false.
        pub enabled: bool,
        /// Whether it may be autonomous.
        pub autonomous: String,
        /// What it needs.
        pub requires: String,
        /// Who may approve.
        pub approver_roles: Vec<String>,
    }
}

strict! {
    /// Auto-merge rules.
    pub struct AutoMerge {
        /// Whether auto-merge is on. Must be false.
        pub enabled: bool,
        /// It is enabled per repository only.
        pub per_repo_opt_in_only: bool,
    }
}

strict! {
    /// Section 1: autonomy.
    pub struct Autonomy {
        /// The level a repository starts at.
        pub default_level: String,
        /// The levels.
        pub levels: Vec<AutonomyLevel>,
        /// Deployment.
        pub deploy: Deploy,
        /// Auto-merge.
        pub auto_merge: AutoMerge,
    }
}

strict! {
    /// Whether a GitHub permission can add a condition.
    pub struct AdditionalCondition {
        /// Whether it applies.
        pub enabled: bool,
        /// The lowest permission.
        pub at_least: String,
        /// It can only deny.
        pub can_only_deny: bool,
    }
}

strict! {
    /// What a GitHub permission is worth.
    pub struct GithubPermission {
        /// Whether it can grant authority. Must be false.
        pub can_grant_authority: bool,
        /// The optional extra condition.
        pub additional_condition: AdditionalCondition,
    }
}

strict! {
    /// Changes to the allow list.
    pub struct AllowlistChanges {
        /// The action that governs a change.
        pub action: String,
        /// The number of distinct organization admins needed.
        pub requires_distinct_org_admins: u32,
        /// Whether a person may grant themselves. Must be false.
        pub self_grant_allowed: bool,
        /// How a change is audited.
        pub audit: String,
    }
}

strict! {
    /// Section 2: where authority comes from.
    pub struct Authority {
        /// The source.
        pub source: String,
        /// Where the allow list lives.
        pub location: String,
        /// Where it may be read from.
        pub read_from: Vec<String>,
        /// Where it must never be read from.
        pub never_read_from: Vec<String>,
        /// The identity key.
        pub identity_key: String,
        /// Whether a login is for display only.
        pub login_is_display_only: bool,
        /// The scope of an entry.
        pub scope: String,
        /// The fields of an entry.
        pub entry_fields: Vec<String>,
        /// Whether entries expire.
        pub entry_expiry: String,
        /// Whether bots may be listed. Must be false.
        pub bots_may_be_listed: bool,
        /// What a GitHub permission is worth.
        pub github_permission: GithubPermission,
        /// Changes to the allow list.
        pub allowlist_changes: AllowlistChanges,
        /// When membership is evaluated.
        pub evaluated: String,
    }
}

strict! {
    /// One role.
    pub struct Role {
        /// The role.
        pub id: String,
        /// The designation on the allow list.
        pub designation: String,
        /// What it may do.
        pub description: String,
        /// Whether it can only be held by a human user.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub must_be_human_user: Option<bool>,
    }
}

strict! {
    /// Separation of duties.
    pub struct SeparationOfDuties {
        /// Cases where the approver must differ from the requester.
        pub approver_must_differ_from_requester_when: Vec<String>,
        /// Whether they may be the same at low risk.
        pub approver_may_equal_requester_when_low_risk: bool,
        /// Whether the factory's App may approve. Must be false.
        pub factory_app_may_approve: bool,
        /// A security approver must differ from the requester.
        pub security_approver_must_differ_from_requester: bool,
    }
}

strict! {
    /// One risk tier.
    pub struct RiskTierRule {
        /// The tier.
        pub id: RiskTier,
        /// Any one of these puts a change in the tier.
        pub criteria_any: Vec<String>,
        /// Reviews required.
        pub required_reviews: Vec<String>,
        /// Approvals required.
        pub required_approvals: u32,
        /// The approver must differ from the requester.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub approver_must_differ_from_requester: Option<bool>,
        /// Roles that may approve.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub approver_roles: Option<Vec<String>>,
    }
}

strict! {
    /// Section 3b: how risk is classified.
    pub struct RiskClassification {
        /// Who computes it.
        pub computed_by: String,
        /// Whether an agent may lower the tier. Must be false.
        pub agent_may_lower_tier: bool,
        /// Whether an agent may raise it.
        pub agent_may_raise_tier: bool,
    }
}

closed_set! {
    /// What an action needs.
    pub enum Requirement {
        /// The policy engine decides from evidence.
        None,
        /// A named human decides.
        Human,
        /// Both a human and the policy engine must agree.
        HumanAndPolicy,
    }
}

closed_set! {
    /// What an action needs at one autonomy level.
    pub enum LevelRequirement {
        /// Not available at this level.
        Forbidden,
        /// The policy engine decides from evidence.
        None,
        /// A named human decides.
        Human,
        /// The policy engine decides, because its preconditions hold.
        Policy,
        /// Both agree.
        HumanAndPolicy,
    }
}

strict! {
    /// One row of the action table. Exactly one of `requires` and `requires_by_level` is present.
    pub struct ActionRule {
        /// The action.
        pub id: String,
        /// The lowest level at which the factory may attempt it.
        pub min_level: String,
        /// What it needs, when that does not depend on the level.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requires: Option<Requirement>,
        /// What it needs at each level.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requires_by_level: Option<BTreeMap<String, LevelRequirement>>,
        /// When it applies.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub when: Option<String>,
        /// Roles that may approve.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub approver_roles: Option<Vec<String>>,
        /// Threats.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub threats: Option<Vec<ThreatId>>,
    }
}

strict! {
    /// Section 6: what an approval is bound to.
    pub struct ApprovalBinding {
        /// What it is bound to.
        pub binds_to: Vec<String>,
        /// A merge must pass the expected head SHA.
        pub github_merge_must_pass_expected_head_sha: bool,
        /// Hours it stays valid.
        pub expires_after_hours: u32,
        /// What invalidates it.
        pub invalidated_by: Vec<String>,
        /// Actions that need step-up authentication.
        pub step_up_authentication_required_for: Vec<String>,
        /// The fields of an approval record.
        pub record_fields: Vec<String>,
    }
}

strict! {
    /// How a command is read from a GitHub comment.
    pub struct GithubComment {
        /// The prefix.
        pub prefix: String,
        /// The syntax.
        pub syntax: String,
        /// The event that carries a command.
        pub accept_event: String,
        /// Only the first line is read.
        pub first_line_only: bool,
        /// Places where a command is ignored.
        pub ignore_inside: Vec<String>,
        /// Only this sender type may command.
        pub ignore_if_sender_type_not: String,
        /// Senders ignored.
        pub ignore_senders: Vec<String>,
        /// How the sender is authorized.
        pub authorization: String,
        /// What an unauthorized sender gets.
        pub unauthorized_response: String,
        /// One command per comment.
        pub one_command_per_comment: bool,
    }
}

strict! {
    /// Rules for the dashboard and the command line.
    pub struct DashboardAndCli {
        /// Authentication.
        pub authentication: String,
        /// CSRF protection.
        pub csrf_protection: String,
        /// Session binding.
        pub session_binding: String,
    }
}

strict! {
    /// Command rate limit.
    pub struct CommandRateLimit {
        /// Per user per minute.
        pub per_user_per_minute: u64,
    }
}

strict! {
    /// Section 7: commands.
    pub struct Commands {
        /// The verbs.
        pub verbs: Vec<String>,
        /// The channels.
        pub channels: Vec<String>,
        /// GitHub comments.
        pub github_comment: GithubComment,
        /// Dashboard and command line.
        pub dashboard_and_cli: DashboardAndCli,
        /// The rate limit.
        pub rate_limit: CommandRateLimit,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// Section 8: intake authorization.
    pub struct Intake {
        /// The label that triggers intake.
        pub trigger_label: String,
        /// Who authorizes.
        pub authorizing_actor: String,
        /// The designation the actor needs.
        pub authorizing_actor_requires_designation: String,
        /// Whether a GitHub permission authorizes. Must be false.
        pub github_permission_is_authorization: bool,
        /// Whether the label alone authorizes. Must be false.
        pub label_presence_alone_is_authorization: bool,
        /// Whether the content hash is recorded at authorization.
        pub snapshot_content_hash_at_authorization: bool,
        /// Whether an edit by someone else needs a new authorization.
        pub reauthorize_on_edit_by_actor_other_than_authorizer: bool,
        /// What an unauthorized request gets.
        pub on_unauthorized: String,
        /// What an out-of-policy request gets.
        pub on_out_of_policy_request: String,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}
