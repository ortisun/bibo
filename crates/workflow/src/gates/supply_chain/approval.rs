//! The human decision on a new direct dependency, and what it is bound to.
//!
//! A new direct dependency always needs a human (ADR 0009 item 4). This module is the record of
//! that decision, and it is made so that it can be made in one way only:
//!
//! * The authority is the policy engine. [`authorize`] asks `AuthorityPolicy::authorize_action`
//!   for the action `add_new_direct_dependency`, with the dependency flag set so that separation
//!   of duties applies, and with the security approver required when the policy decision named
//!   one. [`authorize_build_code`] asks for the action `approve_build_code`, whose row names the
//!   designation that may decide it. The proof, an `AuthorizedApproval`, can only be made by that
//!   engine.
//! * There are two kinds of decision ([`ApprovalKind`]) and one never stands for the other. A
//!   decision on a new direct dependency says that a person accepts the package. A decision on
//!   build code says that a person accepts the build script or the procedural macro of a package
//!   that is new to the build, and it is given for that package, whether or not it came in as a
//!   direct dependency.
//! * [`DependencyApproval::record`] takes that proof. A person is identified by the **numeric
//!   GitHub id** the engine checked against the allowlist, never by a login, which can be
//!   renamed and registered again by someone else.
//! * The approval is bound to the exact name, version and checksum. The same name at another
//!   version, or the same version with another checksum, is another subject and has no
//!   approval until a person decides on it.
//! * It is bound to the tenant and the job it was decided for, and to the hash of the policy
//!   bundle in force when it was decided. The review drops a decision that is for another tenant,
//!   another job or another policy bundle: a decision taken under a weaker policy, or for
//!   another job, does not carry over.
//! * It is written to the ledger evidence with the approver's id, the designation, the version of
//!   the allowlist, the hash of the policy bundle, the tenant, the job and the reason
//!   ([`DependencyApproval::to_json`]). [`DependencyApproval::from_json`] reads it back, and
//!   refuses a record that has no numeric id, no tenant or no job.

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::policy::authority::{
    ActionContext, ActionVerdict, Actor, Allowlist, AuthorityPolicy, AutonomyLevel, ChangeFacts,
};
use factory_domain::policy::decision::{AuthorizedApproval, Designation, GithubUserId};
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_domain::vocabulary::RiskTier;
use serde_json::{Value, json};

use super::model::normalize;

/// The action row of `approval.yaml` for a new direct dependency.
pub const ACTION: &str = "add_new_direct_dependency";

/// The action row of `approval.yaml` for the build code of a package that is new to the build.
pub const BUILD_CODE_ACTION: &str = "approve_build_code";

/// What a recorded decision is about. Each kind is one action row of `approval.yaml`, and a
/// decision of one kind never counts for the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ApprovalKind {
    /// A person accepts a new direct dependency (`add_new_direct_dependency`).
    NewDependency,
    /// A person accepts the build script or the procedural macro of a package that is new to the
    /// build (`approve_build_code`).
    BuildCode,
}

impl ApprovalKind {
    /// The action row of the policy.
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::NewDependency => ACTION,
            Self::BuildCode => BUILD_CODE_ACTION,
        }
    }

    /// The kind of an action row, or `None` for any other action.
    #[must_use]
    pub fn of_action(action: &str) -> Option<Self> {
        [Self::NewDependency, Self::BuildCode]
            .into_iter()
            .find(|kind| kind.action() == action)
    }
}

/// The shortest reason accepted, in characters. A person says why.
pub const MIN_REASON_CHARS: usize = 10;
/// The longest reason kept.
pub const MAX_REASON_CHARS: usize = 500;

/// The exact thing a person approves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// The package name.
    pub name: String,
    /// The version.
    pub version: String,
    /// The checksum of the archive: 64 lowercase hexadecimal digits.
    pub checksum: String,
}

impl Subject {
    /// True when `other` is the same package at the same version with the same checksum.
    #[must_use]
    pub fn same_as(&self, other: &Self) -> bool {
        normalize(&self.name) == normalize(&other.name)
            && self.version == other.version
            && self.checksum == other.checksum
    }
}

/// Where a decision was taken: the tenant and the job it is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionScope {
    /// The tenant.
    pub tenant: TenantId,
    /// The job.
    pub job: JobId,
}

/// Why a decision could not be recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalError {
    /// The proof is for another action.
    #[error("the authorization is for another action")]
    WrongAction,
    /// The reason is missing or too short.
    #[error("a decision needs a reason of at least {MIN_REASON_CHARS} characters")]
    NoReason,
    /// The subject has no valid checksum.
    #[error("the dependency has no valid checksum to bind the decision to")]
    NoChecksum,
}

/// The record of one authorized decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyApproval {
    /// What the decision is about: the package, or its build code.
    pub kind: ApprovalKind,
    /// What was approved.
    pub subject: Subject,
    /// The numeric id of the person.
    pub approver: GithubUserId,
    /// The designation the allowlist gave them, which the decision relied on.
    pub designation: Designation,
    /// The version of the allowlist the decision was read from.
    pub allowlist_version: String,
    /// The hash of the policy bundle in force when it was decided.
    pub policy_hash: Sha256Digest,
    /// The tenant and the job it was decided for.
    pub scope: DecisionScope,
    /// Why, in the person's words.
    pub reason: String,
    /// When.
    pub decided_at: Timestamp,
}

fn sound_checksum(checksum: &str) -> bool {
    checksum.len() == 64 && checksum.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

impl DependencyApproval {
    /// Records a decision.
    ///
    /// # Errors
    /// [`ApprovalError`] when the proof is for another action, the reason is too short, or the
    /// subject has no valid checksum.
    pub fn record(
        authorization: &AuthorizedApproval,
        subject: Subject,
        policy_hash: Sha256Digest,
        scope: DecisionScope,
        reason: &str,
    ) -> Result<Self, ApprovalError> {
        let kind =
            ApprovalKind::of_action(authorization.action()).ok_or(ApprovalError::WrongAction)?;
        let reason = reason.trim();
        if reason.chars().count() < MIN_REASON_CHARS {
            return Err(ApprovalError::NoReason);
        }
        if !sound_checksum(&subject.checksum) {
            return Err(ApprovalError::NoChecksum);
        }
        Ok(Self {
            kind,
            subject,
            approver: authorization.approver(),
            designation: authorization.designation(),
            allowlist_version: authorization.allowlist_version().to_owned(),
            policy_hash,
            scope,
            reason: reason.chars().take(MAX_REASON_CHARS).collect(),
            decided_at: *authorization.decided_at(),
        })
    }

    /// True when this decision is about exactly `subject`.
    #[must_use]
    pub fn covers(&self, subject: &Subject) -> bool {
        self.subject.same_as(subject)
    }

    /// True when this is a decision of `kind` about exactly `subject`.
    #[must_use]
    pub fn is_for(&self, kind: ApprovalKind, subject: &Subject) -> bool {
        self.kind == kind && self.covers(subject)
    }

    /// True when the person who decided holds one of the designations in `needed`, as
    /// [`satisfies`](Self::satisfies) reads each one. An empty list is satisfied by nobody.
    #[must_use]
    pub fn satisfies_any(&self, needed: &[Designation]) -> bool {
        needed
            .iter()
            .any(|designation| self.satisfies(*designation))
    }

    /// True when the decision was taken for this tenant and job, under this policy bundle.
    #[must_use]
    pub fn is_valid_for(&self, scope: &DecisionScope, policy_hash: &Sha256Digest) -> bool {
        self.scope == *scope && self.policy_hash == *policy_hash
    }

    /// True when the person who decided holds a designation that is enough for `needed`. A
    /// security approver can decide what an approver decides; an approver cannot decide what
    /// needs a security approver.
    #[must_use]
    pub fn satisfies(&self, needed: Designation) -> bool {
        match needed {
            Designation::SecurityApprover => self.designation == Designation::SecurityApprover,
            Designation::Approver => matches!(
                self.designation,
                Designation::Approver | Designation::SecurityApprover
            ),
            other => self.designation == other,
        }
    }

    /// The ledger evidence of the decision.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "action": self.kind.action(),
            "ecosystem": "cargo",
            "name": self.subject.name,
            "version": self.subject.version,
            "checksum": self.subject.checksum,
            "approver_id": self.approver.get(),
            "designation": self.designation.as_str(),
            "allowlist_version": self.allowlist_version,
            "policy_hash": self.policy_hash.as_str(),
            "tenant_id": self.scope.tenant.as_text(),
            "job_id": self.scope.job.as_text(),
            "reason": self.reason,
            "decided_at": self.decided_at.as_text(),
        })
    }

    /// Reads a decision written by [`to_json`](Self::to_json). `None` for anything else, which
    /// includes a record that names a person by login and carries no numeric id.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let text = |name: &str| value.get(name).and_then(Value::as_str);
        let kind = ApprovalKind::of_action(text("action")?)?;
        if text("ecosystem")? != "cargo" {
            return None;
        }
        let checksum = text("checksum")?;
        let reason = text("reason")?;
        if !sound_checksum(checksum) || reason.chars().count() < MIN_REASON_CHARS {
            return None;
        }
        Some(Self {
            kind,
            subject: Subject {
                name: text("name")?.to_owned(),
                version: text("version")?.to_owned(),
                checksum: checksum.to_owned(),
            },
            approver: GithubUserId::new(value.get("approver_id")?.as_u64()?)?,
            designation: Designation::parse(text("designation")?)?,
            allowlist_version: text("allowlist_version")?.to_owned(),
            policy_hash: Sha256Digest::parse(text("policy_hash")?).ok()?,
            scope: DecisionScope {
                tenant: TenantId::parse(text("tenant_id")?).ok()?,
                job: JobId::parse(text("job_id")?).ok()?,
            },
            reason: reason.to_owned(),
            decided_at: Timestamp::parse(text("decided_at")?).ok()?,
        })
    }
}

/// The decisions recorded for a job, as the composition root reads them from the ledger.
///
/// The implementation loads by tenant and job, and only the rows written by the approval command
/// (`authorize` and [`DependencyApproval::record`]). It never reads a decision from the stage
/// output, from an artifact the sandbox wrote or from a file of the repository: those are the
/// candidate's. The gate drops what is for another tenant, job or policy bundle on its own, so
/// this is the second check and not the first.
#[async_trait]
pub trait RecordedApprovals: Send + Sync {
    /// Every decision recorded for `job` of `tenant`.
    async fn for_job(&self, tenant: TenantId, job: JobId) -> Vec<DependencyApproval>;
}

/// A fixed list of decisions, for a source that was filled before the run and for tests.
#[derive(Debug, Clone, Default)]
pub struct StaticApprovals(pub Vec<DependencyApproval>);

#[async_trait]
impl RecordedApprovals for StaticApprovals {
    async fn for_job(&self, tenant: TenantId, job: JobId) -> Vec<DependencyApproval> {
        self.0
            .iter()
            .filter(|approval| approval.scope == DecisionScope { tenant, job })
            .cloned()
            .collect()
    }
}

/// The facts one authorization reads.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The authority evaluator of the policy engine.
    pub policy: &'a AuthorityPolicy,
    /// The repository's effective autonomy level.
    pub level: AutonomyLevel,
    /// The tenant.
    pub tenant: &'a TenantId,
    /// The repository, `owner/name`.
    pub repository: &'a str,
    /// The person who acts. Only the numeric id and the kind decide anything.
    pub actor: &'a Actor<'a>,
    /// The allowlist version in force now.
    pub allowlist: &'a Allowlist,
    /// The time of the decision, from the clock port.
    pub now: &'a Timestamp,
    /// The person who requested the job. They may not approve their own dependency.
    pub requester: Option<GithubUserId>,
    /// The risk tier the policy computed.
    pub risk_tier: RiskTier,
    /// A protected path changes.
    pub protected_path_change: bool,
    /// A sensitive file changes.
    pub sensitive_file_change: bool,
}

/// Asks the policy engine whether `request.actor` may approve the build code of a package that is
/// new to the build. The row `approve_build_code` says who may, and the engine refuses to be
/// built when it names anyone but the security approver. The change is marked as adding a
/// dependency so that separation of duties applies as it does for the dependency itself.
#[must_use]
pub fn authorize_build_code(request: &Request<'_>) -> ActionVerdict {
    ask(request, BUILD_CODE_ACTION, None)
}

/// Asks the policy engine whether `request.actor` may approve a new direct dependency that needs
/// the designation `needed`. The change is marked as adding a dependency so that separation of
/// duties applies, and the security approver is required when `needed` is that designation.
#[must_use]
pub fn authorize(request: &Request<'_>, needed: Designation) -> ActionVerdict {
    ask(
        request,
        ACTION,
        (needed == Designation::SecurityApprover).then_some(Designation::SecurityApprover),
    )
}

fn ask(
    request: &Request<'_>,
    action: &str,
    require_designation: Option<Designation>,
) -> ActionVerdict {
    request.policy.authorize_action(&ActionContext {
        action,
        level: request.level,
        tenant: request.tenant,
        repository: request.repository,
        actor: request.actor,
        allowlist: request.allowlist,
        now: request.now,
        requester: request.requester,
        change: ChangeFacts {
            risk_tier: request.risk_tier,
            protected_path_change: request.protected_path_change,
            sensitive_file_change: request.sensitive_file_change,
            new_dependency: true,
        },
        require_designation,
        step_up_done: false,
    })
}
