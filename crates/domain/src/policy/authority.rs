//! Who may do what (`policies/approval.yaml`): the authority allowlist, the autonomy ladder, the
//! action table, separation of duties, overrides and admission.
//!
//! # Authority comes from the allowlist and from nothing else
//!
//! A person holds a designation (`requester`, `operator`, `approver`, `security_approver`,
//! `repo_admin`, `org_admin`) by being named for it on the tenant's allowlist, found by the
//! **numeric GitHub user id**. This module never reads a login, a GitHub repository permission
//! or an `author_association` to grant anything. A login is carried in [`Actor`] only so that
//! audit events can show it. The optional permission condition of the policy can only deny.
//! Membership is read from the allowlist passed to each call, at decision time, and nothing is
//! cached. A bot or an app is never granted a designation, whatever the allowlist says.
//!
//! # What an authorization is
//!
//! [`AuthorityPolicy::authorize_action`] answers for one human who wants to take one action. It
//! checks, in this order, and the first failure is the answer: the actor is a human user; the
//! action is not on the never-allowed list; the repository's level is enabled and at least the
//! action's `min_level`; the action's requirement at that level is not `forbidden`; the actor is
//! on the allowlist for this tenant and repository and the entry has not expired; the actor holds
//! a designation the action names; separation of duties allows it; and step-up authentication was
//! done when the policy asks for it. An action on the `always_human` list never needs less than a
//! human, whatever its row says. An action that has no row needs a human with the `org_admin`
//! designation (the policy's `default_action`).
//!
//! The result is an [`AuthorizedApproval`], which only this module can make. A function that needs
//! a recorded human decision, such as the protected-path exception, takes one.

use std::collections::{BTreeMap, BTreeSet};

use crate::contracts::gate_report::BlockedCode;
use crate::ids::TenantId;
use crate::machines::guards::stage_run::override_permitted;
use crate::machines::guards::{AdmissionFacts, OverrideFacts, job::admission_ok};
use crate::values::Timestamp;
use crate::vocabulary::{HumanRole, RiskTier};

use super::approval::{ApprovalPolicy, LevelRequirement, Requirement};
use super::decision::{AuthorizedApproval, Designation, GithubUserId};
use super::security::SecurityPolicy;
use super::{BuildError, RuleRef};

/// The autonomy ladder. A higher level lets the factory do more without a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AutonomyLevel {
    /// Observe only.
    L0,
    /// Draft pull requests; every promotion needs a human.
    L1,
    /// May mark a pull request ready; a human merges.
    L2,
    /// Auto-merge of low-risk changes. Off.
    L3,
}

impl AutonomyLevel {
    /// Every level, lowest first.
    pub const ALL: [AutonomyLevel; 4] = [Self::L0, Self::L1, Self::L2, Self::L3];

    /// The policy spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
        }
    }

    /// Reads the policy spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.as_str() == text)
    }
}

/// What kind of account is acting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    /// A person's account (`sender.type == User`).
    User,
    /// A bot account.
    Bot,
    /// A GitHub App, including the factory's own.
    App,
}

/// The repository permission GitHub reports for an account. It can only deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GithubPermission {
    /// None.
    None,
    /// Read.
    Read,
    /// Triage.
    Triage,
    /// Write.
    Write,
    /// Maintain.
    Maintain,
    /// Admin.
    Admin,
}

impl GithubPermission {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "none" => Some(Self::None),
            "read" => Some(Self::Read),
            "triage" => Some(Self::Triage),
            "write" => Some(Self::Write),
            "maintain" => Some(Self::Maintain),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

/// The account that acts. Only `github_user_id` and `kind` decide anything.
#[derive(Debug, Clone, Copy)]
pub struct Actor<'a> {
    /// The immutable numeric id, the only key authority is looked up by.
    pub github_user_id: GithubUserId,
    /// The login, for display and audit. Never used to decide.
    pub login: &'a str,
    /// The kind of account.
    pub kind: ActorKind,
    /// The repository permission GitHub reports, if the caller looked it up. Used only when the
    /// policy turns its deny-only condition on.
    pub github_permission: Option<GithubPermission>,
    /// The `author_association` of the webhook payload. Never used to decide.
    pub author_association: Option<&'a str>,
}

/// One person on the allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistEntry {
    /// The tenant the entry belongs to.
    pub tenant: TenantId,
    /// The person, by numeric id.
    pub github_user_id: GithubUserId,
    /// The login at the time the entry was written, for display.
    pub login: String,
    /// What they hold.
    pub designations: BTreeSet<Designation>,
    /// The repositories (`owner/name`) the entry is narrowed to. `None` means all of the tenant's.
    pub repositories: Option<BTreeSet<String>>,
    /// When the entry stops granting authority.
    pub expires_at: Option<Timestamp>,
}

impl AllowlistEntry {
    /// True when the entry's designations reach `repository` (`owner/name`).
    ///
    /// An entry with no `repositories` list covers every repository of the tenant. An entry with a
    /// list covers exactly the repositories on it, compared whole and without regard to case (GitHub
    /// names are case-insensitive), so `acme/rep` does not cover `acme/repo` and an empty list covers
    /// none. This can only take authority away: it is asked in addition to the tenant, the numeric
    /// id, the expiry and the designation, never instead of one of them.
    #[must_use]
    pub fn covers_repository(&self, repository: &str) -> bool {
        self.repositories.as_ref().is_none_or(|repositories| {
            repositories
                .iter()
                .any(|listed| listed.eq_ignore_ascii_case(repository))
        })
    }
}

/// Why an allowlist could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AllowlistError {
    /// The same person appears twice for one tenant, so which entry wins would be a guess.
    #[error("the person with id {0} is listed twice for one tenant")]
    DuplicateEntry(GithubUserId),
}

/// A version of the named allowlist, read from protected configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    version_hash: String,
    entries: BTreeMap<(TenantId, GithubUserId), AllowlistEntry>,
}

impl Allowlist {
    /// Builds an allowlist from its entries and the hash of the version they came from.
    ///
    /// # Errors
    /// [`AllowlistError::DuplicateEntry`] when a person is listed twice for one tenant.
    pub fn new(
        version_hash: impl Into<String>,
        entries: Vec<AllowlistEntry>,
    ) -> Result<Self, AllowlistError> {
        let mut map = BTreeMap::new();
        for entry in entries {
            let key = (entry.tenant, entry.github_user_id);
            if map.insert(key, entry).is_some() {
                return Err(AllowlistError::DuplicateEntry(key.1));
            }
        }
        Ok(Self {
            version_hash: version_hash.into(),
            entries: map,
        })
    }

    /// The version hash, recorded on every decision.
    #[must_use]
    pub fn version_hash(&self) -> &str {
        &self.version_hash
    }
}

/// Why an actor has no authority. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityDenial {
    /// The account is a bot or an app. Designations apply to human users only.
    #[error("the account is not a human user")]
    NotHuman,
    /// The numeric id is not on the allowlist for this tenant.
    #[error("the account is not on the allowlist")]
    NotOnAllowlist,
    /// The entry has expired.
    #[error("the allowlist entry has expired")]
    EntryExpired,
    /// The entry is narrowed to other repositories.
    #[error("the allowlist entry does not cover this repository")]
    RepositoryNotListed,
    /// The policy's deny-only permission condition is on and the account does not meet it.
    #[error("the account does not meet the additional GitHub permission condition")]
    GithubPermissionBelowCondition,
}

/// Why an action was refused. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionDenialReason {
    /// The actor has no authority at all.
    Authority(AuthorityDenial),
    /// The action is on the list nobody may do through the factory, with a human or without.
    NeverAllowed,
    /// The repository's autonomy level is below the action's `min_level`.
    BelowMinLevel,
    /// The level is turned off in the policy (L3).
    LevelDisabled,
    /// The action is `forbidden` at this level.
    ForbiddenAtLevel,
    /// The actor holds none of the designations the action names.
    MissingDesignation {
        /// The designations that would have done.
        needed: Vec<Designation>,
    },
    /// The actor is the requester and separation of duties forbids it.
    SelfApproval,
    /// Separation of duties applies and the requester is not known.
    RequesterUnknown,
    /// The action needs step-up authentication and it was not done.
    StepUpRequired,
}

/// A refused action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionDenial {
    /// Why.
    pub reason: ActionDenialReason,
    /// The rule: an action row, a list or a section.
    pub rule: RuleRef,
}

/// The answer for one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionVerdict {
    /// An authorized human may take the action. Keep the record.
    Authorized(AuthorizedApproval),
    /// The action's requirement here is `none` or `policy`: no human is needed, the policy engine
    /// decides from evidence.
    NoHumanNeeded {
        /// The action row.
        rule: RuleRef,
    },
    /// Refused.
    Denied(ActionDenial),
}

/// Facts about the change that separation of duties and the risk tier read.
#[derive(Debug, Clone, Copy)]
pub struct ChangeFacts {
    /// The tier the policy computed.
    pub risk_tier: RiskTier,
    /// A protected path changes.
    pub protected_path_change: bool,
    /// A sensitive file changes.
    pub sensitive_file_change: bool,
    /// A new direct dependency is added.
    pub new_dependency: bool,
}

/// Everything one action decision reads.
#[derive(Debug, Clone, Copy)]
pub struct ActionContext<'a> {
    /// The action id, such as `merge_pr`.
    pub action: &'a str,
    /// The repository's effective autonomy level.
    pub level: AutonomyLevel,
    /// The tenant.
    pub tenant: &'a TenantId,
    /// The repository, `owner/name`.
    pub repository: &'a str,
    /// The acting account.
    pub actor: &'a Actor<'a>,
    /// The allowlist version in force now.
    pub allowlist: &'a Allowlist,
    /// The time of the decision, from the clock port.
    pub now: &'a Timestamp,
    /// The numeric id of the person who requested the job, when known.
    pub requester: Option<GithubUserId>,
    /// Facts about the change.
    pub change: ChangeFacts,
    /// A designation that replaces the action's own list: a security approver for a dependency
    /// younger than the minimum age, for example, where the action row names an ordinary
    /// approver. Exactly one designation can satisfy the check then.
    pub require_designation: Option<Designation>,
    /// Whether the actor passed step-up authentication for this decision.
    pub step_up_done: bool,
}

/// A change to the authority allowlist that is being approved.
#[derive(Debug, Clone, Copy)]
pub struct AllowlistChange {
    /// The person whose entry changes.
    pub beneficiary: GithubUserId,
    /// The change adds or widens `security_approver` or `org_admin`.
    pub adds_or_widens_high_designation: bool,
}

/// Why an allowlist change was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AllowlistChangeDenial {
    /// An approval is for another action.
    #[error("an approval is for another action")]
    WrongAction,
    /// The beneficiary is one of the approvers: nobody grants themselves authority.
    #[error("nobody can approve a change to their own authority")]
    SelfGrant,
    /// Fewer distinct organization administrators approved than the policy needs.
    #[error("too few distinct organization administrators approved")]
    TooFewApprovers,
}

/// What an override of a blocked gate needs.
#[derive(Debug, Clone, Copy)]
pub struct OverrideContext<'a> {
    /// The blocked gate, such as `protected_path_check`.
    pub gate: &'a str,
    /// The block code of the gate report that blocked it, such as `policy_unresolvable`.
    pub block_code: &'a str,
    /// The block is a security-class block.
    pub block_is_security_class: bool,
    /// The gate is a mandatory gate of an active domain profile (INV-07).
    pub gate_is_mandatory_of_active_profile: bool,
    /// The written justification.
    pub justification: &'a str,
    /// The owner the waiver names.
    pub owner: Option<GithubUserId>,
    /// When the waiver expires.
    pub expires_at: Option<&'a Timestamp>,
}

/// Why an override was refused. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideDenial {
    /// The gate is on `gate_integrity.nonwaivable_gates`.
    NonWaivableGate,
    /// The gate is a mandatory gate of an active domain profile (INV-07).
    MandatoryGateOfActiveProfile,
    /// The policy lists this gate with this block code as a block no override may pass
    /// (`gate_integrity.non_overridable_blocks`). A person records the decision the gate waits
    /// for, and the stage is run again.
    NoOverrideForBlock,
    /// The justification is empty.
    NoJustification,
    /// The waiver has no owner, or no expiry, or an expiry that has passed.
    NoOwnerOrExpiry,
    /// The actor may not waive: see the action denial.
    Action(ActionDenial),
}

/// A permitted override. It records accepted residual risk and never an assurance level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverrideGrant {
    /// The human decision.
    pub approval: AuthorizedApproval,
    /// Always true: an override accepts residual risk.
    pub residual_risk_accepted: bool,
    /// Always false: an override never creates an assurance-level claim.
    pub creates_assurance_claim: bool,
}

/// Admission of a request (`G_ADMISSION_OK`).
#[derive(Debug, Clone, Copy)]
pub struct AdmissionInput<'a> {
    /// The tenant.
    pub tenant: &'a TenantId,
    /// The repository, `owner/name`.
    pub repository: &'a str,
    /// The person who applied the label, not the issue author.
    pub actor: &'a Actor<'a>,
    /// The allowlist version in force now.
    pub allowlist: &'a Allowlist,
    /// The time of the decision.
    pub now: &'a Timestamp,
    /// The tenant is within its job quota.
    pub tenant_within_job_quota: bool,
    /// The repository is registered and enabled.
    pub repository_registered_and_enabled: bool,
    /// Policy allows this class of request.
    pub policy_allows_request_class: bool,
    /// The repository passed the protection preflight.
    pub protection_preflight_passed: bool,
}

/// The answer for admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// The request is admitted, and the job may run at most at `max_level`.
    Admitted {
        /// `L0` when the preflight failed, otherwise the policy's default level.
        max_level: AutonomyLevel,
    },
    /// Not admitted. The reason is for the audit event. The reply to the person is the same
    /// whatever the reason, so that it is no oracle for which check failed.
    Denied {
        /// The conditions that failed.
        unmet: Vec<&'static str>,
    },
}

#[derive(Debug)]
struct Level {
    enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Need {
    Forbidden,
    Nothing,
    Human,
}

#[derive(Debug)]
struct Action {
    min_level: AutonomyLevel,
    by_level: BTreeMap<AutonomyLevel, Need>,
    roles: Vec<Designation>,
}

#[derive(Debug)]
struct TierRule {
    approvals: u32,
    roles: Vec<Designation>,
    differ_from_requester: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SodCondition {
    HighRisk,
    ProtectedPath,
    SensitiveFile,
    NewDependency,
}

/// The actions whose approver is also limited by the risk tier of the change (the tier's
/// `approver_roles` replace the action's own).
const TIERED_ACTIONS: [&str; 4] = [
    "approve_pr",
    "mark_pr_ready",
    "merge_pr",
    "freeze_specification",
];

/// The authority rules of one pair of policies.
#[derive(Debug)]
pub struct AuthorityPolicy {
    levels: BTreeMap<AutonomyLevel, Level>,
    default_level: AutonomyLevel,
    actions: BTreeMap<String, Action>,
    always_human: BTreeSet<String>,
    never_allowed: BTreeSet<String>,
    sod_when: BTreeSet<SodCondition>,
    equal_allowed_when_low_risk: bool,
    security_approver_differs: bool,
    tiers: BTreeMap<RiskTier, TierRule>,
    step_up: BTreeSet<String>,
    permission_condition: Option<GithubPermission>,
    distinct_org_admins: u32,
    nonwaivable_gates: BTreeSet<String>,
    /// The (gate, block code) pairs that no override may pass.
    non_overridable_blocks: BTreeSet<(String, String)>,
}

/// The block that must always be on the list: a new direct dependency waits for a recorded human
/// decision on its name, version and checksum, and an override would pass the stage without one.
const UNRESOLVED_DEPENDENCY_REVIEW: (&str, &str) = ("dependency-review", "policy_unresolvable");

fn designation_list(key: &'static str, names: &[String]) -> Result<Vec<Designation>, BuildError> {
    names
        .iter()
        .map(|n| {
            Designation::parse(n).ok_or_else(|| BuildError::UnknownValue {
                key,
                found: n.clone(),
            })
        })
        .collect()
}

fn must_be(key: &'static str, expected: bool, found: bool) -> Result<(), BuildError> {
    if expected == found {
        Ok(())
    } else {
        Err(BuildError::ProtectionDisabled {
            key,
            found: found.to_string(),
        })
    }
}

fn must_equal(key: &'static str, expected: &str, found: &str) -> Result<(), BuildError> {
    if expected == found {
        Ok(())
    } else {
        Err(BuildError::UnknownValue {
            key,
            found: found.to_owned(),
        })
    }
}

impl AuthorityPolicy {
    /// Reads the authority rules.
    ///
    /// # Errors
    /// A [`BuildError`] when a document turns off a rule this engine always applies (GitHub
    /// permission granting authority, bots on the allowlist, self-grant, an agent lowering its own
    /// risk tier), when a name does not parse, or when the action table contradicts `always_human`
    /// or the never-allowed list.
    pub fn from_policies(
        approval: &ApprovalPolicy,
        security: &SecurityPolicy,
    ) -> Result<Self, BuildError> {
        let a = &approval.authority;
        must_equal("authority.source", "named_allowlist", &a.source)?;
        must_equal(
            "authority.identity_key",
            "github_user_numeric_id",
            &a.identity_key,
        )?;
        must_equal(
            "authority.evaluated",
            "at_decision_time_not_cached",
            &a.evaluated,
        )?;
        must_be(
            "authority.login_is_display_only",
            true,
            a.login_is_display_only,
        )?;
        must_be("authority.bots_may_be_listed", false, a.bots_may_be_listed)?;
        must_be(
            "authority.github_permission.can_grant_authority",
            false,
            a.github_permission.can_grant_authority,
        )?;
        must_be(
            "authority.github_permission.additional_condition.can_only_deny",
            true,
            a.github_permission.additional_condition.can_only_deny,
        )?;
        must_be(
            "authority.allowlist_changes.self_grant_allowed",
            false,
            a.allowlist_changes.self_grant_allowed,
        )?;
        must_be(
            "separation_of_duties.factory_app_may_approve",
            false,
            approval.separation_of_duties.factory_app_may_approve,
        )?;
        must_be(
            "separation_of_duties.security_approver_must_differ_from_requester",
            true,
            approval
                .separation_of_duties
                .security_approver_must_differ_from_requester,
        )?;
        must_be(
            "risk_classification.agent_may_lower_tier",
            false,
            approval.risk_classification.agent_may_lower_tier,
        )?;
        must_be(
            "intake.github_permission_is_authorization",
            false,
            approval.intake.github_permission_is_authorization,
        )?;
        must_be(
            "intake.label_presence_alone_is_authorization",
            false,
            approval.intake.label_presence_alone_is_authorization,
        )?;
        let permission_condition = if a.github_permission.additional_condition.enabled {
            Some(
                GithubPermission::parse(&a.github_permission.additional_condition.at_least)
                    .ok_or_else(|| BuildError::UnknownValue {
                        key: "authority.github_permission.additional_condition.at_least",
                        found: a.github_permission.additional_condition.at_least.clone(),
                    })?,
            )
        } else {
            None
        };

        for role in &approval.roles {
            Designation::parse(&role.designation).ok_or_else(|| BuildError::UnknownValue {
                key: "roles.designation",
                found: role.designation.clone(),
            })?;
        }

        let mut levels = BTreeMap::new();
        for l in &approval.autonomy.levels {
            let id = AutonomyLevel::parse(&l.id).ok_or_else(|| BuildError::UnknownValue {
                key: "autonomy.levels.id",
                found: l.id.clone(),
            })?;
            let level = Level {
                enabled: l.enabled.unwrap_or(true),
            };
            if levels.insert(id, level).is_some() {
                return Err(BuildError::Duplicate {
                    what: "autonomy level",
                    name: l.id.clone(),
                });
            }
        }
        for level in AutonomyLevel::ALL {
            if !levels.contains_key(&level) {
                return Err(BuildError::Contradiction(format!(
                    "autonomy.levels has no {}",
                    level.as_str()
                )));
            }
        }
        let default_level =
            AutonomyLevel::parse(&approval.autonomy.default_level).ok_or_else(|| {
                BuildError::UnknownValue {
                    key: "autonomy.default_level",
                    found: approval.autonomy.default_level.clone(),
                }
            })?;
        if !levels.get(&default_level).is_some_and(|l| l.enabled) {
            return Err(BuildError::Contradiction(
                "autonomy.default_level names a level that is turned off".to_owned(),
            ));
        }
        if approval.autonomy.auto_merge.enabled || approval.autonomy.deploy.enabled {
            // The levels carry the switch. A top-level switch the engine does not model is
            // refused rather than ignored.
            return Err(BuildError::ProtectionDisabled {
                key: "autonomy.auto_merge.enabled / autonomy.deploy.enabled",
                found: "true".to_owned(),
            });
        }

        let always_human: BTreeSet<String> = approval.always_human.iter().cloned().collect();
        let never_allowed: BTreeSet<String> = approval
            .never_allowed_even_with_human_via_the_factory
            .iter()
            .cloned()
            .collect();

        let mut actions = BTreeMap::new();
        for row in &approval.actions {
            let min_level =
                AutonomyLevel::parse(&row.min_level).ok_or_else(|| BuildError::UnknownValue {
                    key: "actions.min_level",
                    found: row.min_level.clone(),
                })?;
            let by_level = match (&row.requires, &row.requires_by_level) {
                (Some(req), None) => {
                    let need = match req {
                        Requirement::None => Need::Nothing,
                        Requirement::Human | Requirement::HumanAndPolicy => Need::Human,
                    };
                    AutonomyLevel::ALL.into_iter().map(|l| (l, need)).collect()
                }
                (None, Some(map)) => {
                    let mut out = BTreeMap::new();
                    for (level, req) in map {
                        let id = AutonomyLevel::parse(level).ok_or_else(|| {
                            BuildError::UnknownValue {
                                key: "actions.requires_by_level",
                                found: level.clone(),
                            }
                        })?;
                        let need = match req {
                            LevelRequirement::Forbidden => Need::Forbidden,
                            LevelRequirement::None | LevelRequirement::Policy => Need::Nothing,
                            LevelRequirement::Human | LevelRequirement::HumanAndPolicy => {
                                Need::Human
                            }
                        };
                        out.insert(id, need);
                    }
                    out
                }
                _ => {
                    return Err(BuildError::Contradiction(format!(
                        "action {} must have exactly one of `requires` and `requires_by_level`",
                        row.id
                    )));
                }
            };
            let roles = designation_list(
                "actions.approver_roles",
                row.approver_roles.as_deref().unwrap_or_default(),
            )?;
            let needs_human = by_level.values().any(|n| *n == Need::Human);
            if needs_human && roles.is_empty() {
                return Err(BuildError::Contradiction(format!(
                    "action {} needs a human and names no approver role",
                    row.id
                )));
            }
            if always_human.contains(&row.id) && by_level.values().any(|n| *n == Need::Nothing) {
                return Err(BuildError::Contradiction(format!(
                    "action {} is on always_human but its row lets it happen without a human",
                    row.id
                )));
            }
            if never_allowed.contains(&row.id) {
                return Err(BuildError::Contradiction(format!(
                    "action {} is on the never-allowed list but has a row",
                    row.id
                )));
            }
            if actions
                .insert(
                    row.id.clone(),
                    Action {
                        min_level,
                        by_level,
                        roles,
                    },
                )
                .is_some()
            {
                return Err(BuildError::Duplicate {
                    what: "action",
                    name: row.id.clone(),
                });
            }
        }

        let sod = &approval.separation_of_duties;
        let mut sod_when = BTreeSet::new();
        for name in &sod.approver_must_differ_from_requester_when {
            sod_when.insert(match name.as_str() {
                "risk_tier_at_least_high" => SodCondition::HighRisk,
                "protected_path_change" => SodCondition::ProtectedPath,
                "sensitive_file_change" => SodCondition::SensitiveFile,
                "new_dependency" => SodCondition::NewDependency,
                other => {
                    return Err(BuildError::UnknownValue {
                        key: "separation_of_duties.approver_must_differ_from_requester_when",
                        found: other.to_owned(),
                    });
                }
            });
        }

        let mut tiers = BTreeMap::new();
        for t in &approval.risk_tiers {
            let rule = TierRule {
                approvals: t.required_approvals,
                roles: designation_list(
                    "risk_tiers.approver_roles",
                    t.approver_roles.as_deref().unwrap_or_default(),
                )?,
                differ_from_requester: t.approver_must_differ_from_requester.unwrap_or(false),
            };
            if tiers.insert(t.id, rule).is_some() {
                return Err(BuildError::Duplicate {
                    what: "risk tier",
                    name: t.id.as_str().to_owned(),
                });
            }
        }
        for tier in [
            RiskTier::Low,
            RiskTier::Medium,
            RiskTier::High,
            RiskTier::Critical,
        ] {
            if !tiers.contains_key(&tier) {
                return Err(BuildError::Contradiction(format!(
                    "risk_tiers has no {}",
                    tier.as_str()
                )));
            }
        }

        let mut non_overridable_blocks = BTreeSet::new();
        for block in &security.gate_integrity.non_overridable_blocks {
            BlockedCode::parse(&block.code).map_err(|_| BuildError::UnknownValue {
                key: "gate_integrity.non_overridable_blocks.code",
                found: block.code.clone(),
            })?;
            if !non_overridable_blocks.insert((block.gate.clone(), block.code.clone())) {
                return Err(BuildError::Duplicate {
                    what: "non-overridable block",
                    name: format!("{} {}", block.gate, block.code),
                });
            }
        }
        if !non_overridable_blocks.contains(&(
            UNRESOLVED_DEPENDENCY_REVIEW.0.to_owned(),
            UNRESOLVED_DEPENDENCY_REVIEW.1.to_owned(),
        )) {
            return Err(BuildError::ProtectionDisabled {
                key: "gate_integrity.non_overridable_blocks",
                found: format!(
                    "no entry for {} {}",
                    UNRESOLVED_DEPENDENCY_REVIEW.0, UNRESOLVED_DEPENDENCY_REVIEW.1
                ),
            });
        }

        Ok(Self {
            levels,
            default_level,
            actions,
            always_human,
            never_allowed,
            sod_when,
            equal_allowed_when_low_risk: sod.approver_may_equal_requester_when_low_risk,
            security_approver_differs: sod.security_approver_must_differ_from_requester,
            tiers,
            step_up: approval
                .approval_binding
                .step_up_authentication_required_for
                .iter()
                .cloned()
                .collect(),
            permission_condition,
            distinct_org_admins: a.allowlist_changes.requires_distinct_org_admins,
            nonwaivable_gates: security
                .gate_integrity
                .nonwaivable_gates
                .iter()
                .cloned()
                .collect(),
            non_overridable_blocks,
        })
    }

    /// The level a repository starts at.
    #[must_use]
    pub fn default_level(&self) -> AutonomyLevel {
        self.default_level
    }

    /// True when the level is turned on in the policy.
    #[must_use]
    pub fn level_enabled(&self, level: AutonomyLevel) -> bool {
        self.levels.get(&level).is_some_and(|l| l.enabled)
    }

    /// The level a job may actually run at: the configured level, capped at `L0` when the
    /// protection preflight failed, and capped at the highest level that is turned on. A level
    /// that is turned off (`L3`) is never reached by configuration.
    #[must_use]
    pub fn effective_level(
        &self,
        configured: AutonomyLevel,
        protection_preflight_passed: bool,
    ) -> AutonomyLevel {
        if !protection_preflight_passed {
            return AutonomyLevel::L0;
        }
        AutonomyLevel::ALL
            .into_iter()
            .rev()
            .filter(|l| *l <= configured)
            .find(|l| self.level_enabled(*l))
            .unwrap_or(AutonomyLevel::L0)
    }

    /// True when the action has a row and needs a human at every level (or is forbidden there).
    #[must_use]
    pub fn always_needs_human(&self, action: &str) -> bool {
        self.actions
            .get(action)
            .is_some_and(|a| a.by_level.values().all(|n| *n != Need::Nothing))
    }

    /// The designations the action row names as approvers, in the order of the row. Empty when
    /// the action has no row (such an action needs an organization administrator by the policy's
    /// default). A caller that must know who may decide an action asks here instead of naming a
    /// designation of its own, so the row is the one place that says it.
    #[must_use]
    pub fn approver_designations(&self, action: &str) -> &[Designation] {
        self.actions
            .get(action)
            .map_or(&[], |row| row.roles.as_slice())
    }

    /// True when the name is on the list of things nobody may do through the factory.
    #[must_use]
    pub fn is_never_allowed(&self, name: &str) -> bool {
        self.never_allowed.contains(name)
    }

    /// True when the gate cannot be waived (`gate_integrity.nonwaivable_gates`).
    #[must_use]
    pub fn is_nonwaivable_gate(&self, gate: &str) -> bool {
        self.nonwaivable_gates.contains(gate)
    }

    /// True when policy permits an override of a block of `gate` with `code`
    /// (`gate_integrity.non_overridable_blocks` lists the ones it does not). This is the
    /// `policy_permits_override_for_block_code` fact of guard `G_OVERRIDE_PERMITTED`, computed
    /// from the policy so that no caller asserts it.
    #[must_use]
    pub fn block_may_be_overridden(&self, gate: &str, code: &str) -> bool {
        !self
            .non_overridable_blocks
            .contains(&(gate.to_owned(), code.to_owned()))
    }

    /// The designations an actor holds, or why they hold none.
    ///
    /// # Errors
    /// The [`AuthorityDenial`] for the first failing check.
    pub fn designations(
        &self,
        allowlist: &Allowlist,
        tenant: &TenantId,
        repository: &str,
        actor: &Actor<'_>,
        now: &Timestamp,
    ) -> Result<BTreeSet<Designation>, AuthorityDenial> {
        if actor.kind != ActorKind::User {
            return Err(AuthorityDenial::NotHuman);
        }
        let entry = allowlist
            .entries
            .get(&(*tenant, actor.github_user_id))
            .ok_or(AuthorityDenial::NotOnAllowlist)?;
        if entry.expires_at.as_ref().is_some_and(|end| end <= now) {
            return Err(AuthorityDenial::EntryExpired);
        }
        if !entry.covers_repository(repository) {
            return Err(AuthorityDenial::RepositoryNotListed);
        }
        if let Some(at_least) = self.permission_condition
            && !actor.github_permission.is_some_and(|p| p >= at_least)
        {
            return Err(AuthorityDenial::GithubPermissionBelowCondition);
        }
        Ok(entry.designations.clone())
    }

    /// Admission of a request. The person who applied the label must hold the `requester`
    /// designation on the allowlist, found by numeric id.
    #[must_use]
    pub fn admit(&self, input: &AdmissionInput<'_>) -> Admission {
        let requester_on_allowlist = self
            .designations(
                input.allowlist,
                input.tenant,
                input.repository,
                input.actor,
                input.now,
            )
            .is_ok_and(|d| d.contains(&Designation::Requester));
        let facts = AdmissionFacts {
            requester_on_allowlist,
            tenant_within_job_quota: input.tenant_within_job_quota,
            repository_registered_and_enabled: input.repository_registered_and_enabled,
            policy_allows_request_class: input.policy_allows_request_class,
            protection_preflight_passed: input.protection_preflight_passed,
        };
        match admission_ok(&facts) {
            Ok(()) => Admission::Admitted {
                max_level: self
                    .effective_level(self.default_level, facts.protection_preflight_passed),
            },
            Err(failure) => Admission::Denied {
                unmet: failure.unmet,
            },
        }
    }

    /// The number of distinct approvals a tier needs.
    #[must_use]
    pub fn required_approvals(&self, tier: RiskTier) -> u32 {
        self.tiers.get(&tier).map_or(u32::MAX, |t| t.approvals)
    }

    /// True when `approvals` hold enough distinct approvers for the tier: each for the action,
    /// each approver counted once, each holding a designation the tier names.
    #[must_use]
    pub fn quorum_met(
        &self,
        tier: RiskTier,
        action: &str,
        approvals: &[AuthorizedApproval],
    ) -> bool {
        let Some(rule) = self.tiers.get(&tier) else {
            return false;
        };
        let distinct: BTreeSet<GithubUserId> = approvals
            .iter()
            .filter(|a| a.action() == action)
            .filter(|a| rule.roles.is_empty() || rule.roles.contains(&a.designation()))
            .map(AuthorizedApproval::approver)
            .collect();
        u32::try_from(distinct.len()).is_ok_and(|n| n >= rule.approvals)
    }

    fn denied(reason: ActionDenialReason, rule: RuleRef) -> ActionVerdict {
        ActionVerdict::Denied(ActionDenial { reason, rule })
    }

    /// Decides whether a human may take an action. See the module notes for the order of checks.
    #[must_use]
    pub fn authorize_action(&self, ctx: &ActionContext<'_>) -> ActionVerdict {
        let row_rule = RuleRef::new("actions", ctx.action);
        if self.never_allowed.contains(ctx.action) {
            return Self::denied(
                ActionDenialReason::NeverAllowed,
                RuleRef::new("never_allowed_even_with_human_via_the_factory", ctx.action),
            );
        }
        let row = self.actions.get(ctx.action);
        let min_level = row.map_or(AutonomyLevel::L0, |r| r.min_level);
        if !self.level_enabled(ctx.level) {
            return Self::denied(
                ActionDenialReason::LevelDisabled,
                RuleRef::new("autonomy.levels", ctx.level.as_str()),
            );
        }
        if ctx.level < min_level {
            return Self::denied(ActionDenialReason::BelowMinLevel, row_rule);
        }
        let mut need = match row {
            Some(r) => r.by_level.get(&ctx.level).copied().unwrap_or(Need::Human),
            None => Need::Human,
        };
        if need == Need::Nothing && self.always_human.contains(ctx.action) {
            need = Need::Human;
        }
        match need {
            Need::Forbidden => {
                return Self::denied(ActionDenialReason::ForbiddenAtLevel, row_rule);
            }
            Need::Nothing => return ActionVerdict::NoHumanNeeded { rule: row_rule },
            Need::Human => {}
        }

        let held = match self.designations(
            ctx.allowlist,
            ctx.tenant,
            ctx.repository,
            ctx.actor,
            ctx.now,
        ) {
            Ok(held) => held,
            Err(denial) => {
                return Self::denied(
                    ActionDenialReason::Authority(denial),
                    RuleRef::new("authority", "named_allowlist"),
                );
            }
        };

        let mut needed: Vec<Designation> = match row {
            Some(r) => r.roles.clone(),
            None => vec![Designation::OrgAdmin],
        };
        let tier_rule = self.tiers.get(&ctx.change.risk_tier);
        if TIERED_ACTIONS.contains(&ctx.action)
            && let Some(tier) = tier_rule
            && !tier.roles.is_empty()
        {
            needed = tier.roles.clone();
        }
        if let Some(extra) = ctx.require_designation {
            needed.retain(|d| *d == extra);
            if needed.is_empty() {
                needed.push(extra);
            }
        }
        let Some(used) = needed.iter().copied().find(|d| held.contains(d)) else {
            return Self::denied(ActionDenialReason::MissingDesignation { needed }, row_rule);
        };

        if let Some(denial) = self.separation_of_duties(ctx, used, tier_rule) {
            return Self::denied(denial, RuleRef::new("separation_of_duties", ctx.action));
        }
        if self.step_up.contains(ctx.action) && !ctx.step_up_done {
            return Self::denied(
                ActionDenialReason::StepUpRequired,
                RuleRef::new(
                    "approval_binding.step_up_authentication_required_for",
                    ctx.action,
                ),
            );
        }
        ActionVerdict::Authorized(AuthorizedApproval::new(
            ctx.action,
            ctx.actor.github_user_id,
            used,
            ctx.allowlist.version_hash(),
            *ctx.now,
            row_rule,
        ))
    }

    fn separation_of_duties(
        &self,
        ctx: &ActionContext<'_>,
        used: Designation,
        tier: Option<&TierRule>,
    ) -> Option<ActionDenialReason> {
        let change = &ctx.change;
        let by_change = (self.sod_when.contains(&SodCondition::HighRisk)
            && change.risk_tier >= RiskTier::High)
            || (self.sod_when.contains(&SodCondition::ProtectedPath)
                && change.protected_path_change)
            || (self.sod_when.contains(&SodCondition::SensitiveFile)
                && change.sensitive_file_change)
            || (self.sod_when.contains(&SodCondition::NewDependency) && change.new_dependency)
            || tier.is_some_and(|t| t.differ_from_requester);
        let by_role = self.security_approver_differs && used == Designation::SecurityApprover;
        match ctx.requester {
            Some(requester) if requester == ctx.actor.github_user_id => {
                (by_change || by_role || !self.equal_allowed_when_low_risk)
                    .then_some(ActionDenialReason::SelfApproval)
            }
            Some(_) => None,
            // A change that triggers the rule belongs to a job, so a missing requester is a
            // mistake of the caller, and the answer is no.
            None => by_change.then_some(ActionDenialReason::RequesterUnknown),
        }
    }

    /// Decides whether the approvals for a change to the allowlist are enough: they are all for
    /// `change_authority_allowlist`, none is the person whose entry changes, and a change that
    /// adds or widens `security_approver` or `org_admin` has the number of distinct
    /// `org_admin` approvers the policy asks for.
    ///
    /// # Errors
    /// The [`AllowlistChangeDenial`] for the first failing check.
    pub fn check_allowlist_change(
        &self,
        change: &AllowlistChange,
        approvals: &[AuthorizedApproval],
    ) -> Result<(), AllowlistChangeDenial> {
        if approvals
            .iter()
            .any(|a| a.action() != "change_authority_allowlist")
        {
            return Err(AllowlistChangeDenial::WrongAction);
        }
        if approvals.iter().any(|a| a.approver() == change.beneficiary) {
            return Err(AllowlistChangeDenial::SelfGrant);
        }
        let needed = if change.adds_or_widens_high_designation {
            self.distinct_org_admins.max(1)
        } else {
            1
        };
        let distinct: BTreeSet<GithubUserId> = approvals
            .iter()
            .filter(|a| a.designation() == Designation::OrgAdmin)
            .map(AuthorizedApproval::approver)
            .collect();
        if u32::try_from(distinct.len()).is_ok_and(|n| n >= needed) {
            Ok(())
        } else {
            Err(AllowlistChangeDenial::TooFewApprovers)
        }
    }

    /// Decides whether a human may raise or lower a repository's autonomy level. Raising needs
    /// `org_admin` and is refused for a level that is turned off. Lowering needs `repo_admin`.
    /// Staying where it is needs nothing and changes nothing.
    #[must_use]
    pub fn authorize_autonomy_change(
        &self,
        ctx: &ActionContext<'_>,
        from: AutonomyLevel,
        to: AutonomyLevel,
    ) -> ActionVerdict {
        let rule = RuleRef::new("autonomy", "raise_autonomy_level");
        if to > from {
            if !self.level_enabled(to) {
                return Self::denied(
                    ActionDenialReason::LevelDisabled,
                    RuleRef::new("autonomy.levels", to.as_str()),
                );
            }
            return self.authorize_with(
                ctx,
                "raise_autonomy_level",
                &[Designation::OrgAdmin],
                rule,
            );
        }
        if to < from {
            return self.authorize_with(
                ctx,
                "lower_autonomy_level",
                &[Designation::RepoAdmin, Designation::OrgAdmin],
                RuleRef::new("autonomy", "lower_autonomy_level"),
            );
        }
        ActionVerdict::NoHumanNeeded { rule }
    }

    fn authorize_with(
        &self,
        ctx: &ActionContext<'_>,
        action: &str,
        roles: &[Designation],
        rule: RuleRef,
    ) -> ActionVerdict {
        let held = match self.designations(
            ctx.allowlist,
            ctx.tenant,
            ctx.repository,
            ctx.actor,
            ctx.now,
        ) {
            Ok(held) => held,
            Err(denial) => {
                return Self::denied(
                    ActionDenialReason::Authority(denial),
                    RuleRef::new("authority", "named_allowlist"),
                );
            }
        };
        let Some(used) = roles.iter().copied().find(|d| held.contains(d)) else {
            return Self::denied(
                ActionDenialReason::MissingDesignation {
                    needed: roles.to_vec(),
                },
                rule,
            );
        };
        if let Some(denial) = self.separation_of_duties(ctx, used, None) {
            return Self::denied(denial, rule);
        }
        ActionVerdict::Authorized(AuthorizedApproval::new(
            action,
            ctx.actor.github_user_id,
            used,
            ctx.allowlist.version_hash(),
            *ctx.now,
            rule,
        ))
    }

    /// Decides whether a human may override (waive) a blocked gate. The gate must not be on the
    /// non-waivable list or be a mandatory gate of an active domain profile (INV-07); the
    /// justification, the owner and an unexpired expiry must be recorded; and the actor must be
    /// authorized for `waive_failed_gate`. The result accepts residual risk and never creates an
    /// assurance-level claim.
    ///
    /// # Errors
    /// The [`OverrideDenial`] for the first failing check.
    pub fn authorize_override(
        &self,
        ctx: &ActionContext<'_>,
        request: &OverrideContext<'_>,
    ) -> Result<OverrideGrant, OverrideDenial> {
        if self.nonwaivable_gates.contains(request.gate) {
            return Err(OverrideDenial::NonWaivableGate);
        }
        if !self.block_may_be_overridden(request.gate, request.block_code) {
            return Err(OverrideDenial::NoOverrideForBlock);
        }
        if request.gate_is_mandatory_of_active_profile {
            return Err(OverrideDenial::MandatoryGateOfActiveProfile);
        }
        if request.justification.trim().is_empty() {
            return Err(OverrideDenial::NoJustification);
        }
        match (request.owner, request.expires_at) {
            (Some(_), Some(end)) if end > ctx.now => {}
            _ => return Err(OverrideDenial::NoOwnerOrExpiry),
        }
        let waiver_ctx = ActionContext {
            action: "waive_failed_gate",
            ..*ctx
        };
        let approval = match self.authorize_action(&waiver_ctx) {
            ActionVerdict::Authorized(approval) => approval,
            ActionVerdict::Denied(denial) => return Err(OverrideDenial::Action(denial)),
            ActionVerdict::NoHumanNeeded { rule } => {
                // A waiver always needs a human. A policy that says otherwise is refused.
                return Err(OverrideDenial::Action(ActionDenial {
                    reason: ActionDenialReason::MissingDesignation {
                        needed: vec![Designation::SecurityApprover],
                    },
                    rule,
                }));
            }
        };
        // The same rule as the state machine's guard, so the two cannot drift apart.
        let security: &[HumanRole] = &[HumanRole::SecurityApprover];
        let nothing: &[HumanRole] = &[];
        let facts = OverrideFacts {
            policy_permits_override_for_block_code: self
                .block_may_be_overridden(request.gate, request.block_code),
            block_is_security_class: request.block_is_security_class,
            principal_roles: if approval.designation() == Designation::SecurityApprover {
                security
            } else {
                nothing
            },
            role_required_by_policy: HumanRole::SecurityApprover,
            justification_recorded: true,
            blocked_gate_is_mandatory_of_active_profile: false,
        };
        if override_permitted(&facts).is_err() {
            return Err(OverrideDenial::Action(ActionDenial {
                reason: ActionDenialReason::MissingDesignation {
                    needed: vec![Designation::SecurityApprover],
                },
                rule: RuleRef::new("actions", "waive_failed_gate"),
            }));
        }
        Ok(OverrideGrant {
            approval,
            residual_risk_accepted: true,
            creates_assurance_claim: false,
        })
    }
}
