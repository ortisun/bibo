//! The human decision on a new direct dependency, and what it is bound to.
//!
//! A new direct dependency always needs a human (ADR 0009 item 4). This module is the record of
//! that decision, and it is made so that it can be made in one way only:
//!
//! * The authority is the policy engine. [`authorize`] asks `AuthorityPolicy::authorize_action`
//!   for the action `add_new_direct_dependency`, with the dependency flag set so that separation
//!   of duties applies, and with the security approver required when the policy decision named
//!   one. The proof, an `AuthorizedApproval`, can only be made by that engine.
//! * [`DependencyApproval::record`] takes that proof. A person is identified by the **numeric
//!   GitHub id** the engine checked against the allowlist, never by a login, which can be
//!   renamed and registered again by someone else.
//! * The approval is bound to the exact name, version and checksum. The same name at another
//!   version, or the same version with another checksum, is another subject and has no
//!   approval until a person decides on it.
//! * It is written to the ledger evidence with the approver's id, the designation, the version of
//!   the allowlist, the hash of the policy bundle and the reason ([`DependencyApproval::to_json`]).
//!   [`DependencyApproval::from_json`] reads it back, and refuses a record that has no numeric id.

use factory_domain::ids::TenantId;
use factory_domain::policy::authority::{
    ActionContext, ActionVerdict, Actor, Allowlist, AuthorityPolicy, AutonomyLevel, ChangeFacts,
};
use factory_domain::policy::decision::{AuthorizedApproval, Designation, GithubUserId};
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_domain::vocabulary::RiskTier;
use serde_json::{Value, json};

use super::model::normalize;

/// The action row of `approval.yaml` that this decision is.
pub const ACTION: &str = "add_new_direct_dependency";

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
        reason: &str,
    ) -> Result<Self, ApprovalError> {
        if authorization.action() != ACTION {
            return Err(ApprovalError::WrongAction);
        }
        let reason = reason.trim();
        if reason.chars().count() < MIN_REASON_CHARS {
            return Err(ApprovalError::NoReason);
        }
        if !sound_checksum(&subject.checksum) {
            return Err(ApprovalError::NoChecksum);
        }
        Ok(Self {
            subject,
            approver: authorization.approver(),
            designation: authorization.designation(),
            allowlist_version: authorization.allowlist_version().to_owned(),
            policy_hash,
            reason: reason.chars().take(MAX_REASON_CHARS).collect(),
            decided_at: *authorization.decided_at(),
        })
    }

    /// True when this decision is about exactly `subject`.
    #[must_use]
    pub fn covers(&self, subject: &Subject) -> bool {
        self.subject.same_as(subject)
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
            "action": ACTION,
            "ecosystem": "cargo",
            "name": self.subject.name,
            "version": self.subject.version,
            "checksum": self.subject.checksum,
            "approver_id": self.approver.get(),
            "designation": self.designation.as_str(),
            "allowlist_version": self.allowlist_version,
            "policy_hash": self.policy_hash.as_str(),
            "reason": self.reason,
            "decided_at": self.decided_at.as_text(),
        })
    }

    /// Reads a decision written by [`to_json`](Self::to_json). `None` for anything else, which
    /// includes a record that names a person by login and carries no numeric id.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let text = |name: &str| value.get(name).and_then(Value::as_str);
        if text("action")? != ACTION || text("ecosystem")? != "cargo" {
            return None;
        }
        let checksum = text("checksum")?;
        let reason = text("reason")?;
        if !sound_checksum(checksum) || reason.chars().count() < MIN_REASON_CHARS {
            return None;
        }
        Some(Self {
            subject: Subject {
                name: text("name")?.to_owned(),
                version: text("version")?.to_owned(),
                checksum: checksum.to_owned(),
            },
            approver: GithubUserId::new(value.get("approver_id")?.as_u64()?)?,
            designation: Designation::parse(text("designation")?)?,
            allowlist_version: text("allowlist_version")?.to_owned(),
            policy_hash: Sha256Digest::parse(text("policy_hash")?).ok()?,
            reason: reason.to_owned(),
            decided_at: Timestamp::parse(text("decided_at")?).ok()?,
        })
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

/// Asks the policy engine whether `request.actor` may approve a new direct dependency that needs
/// the designation `needed`. The change is marked as adding a dependency so that separation of
/// duties applies, and the security approver is required when `needed` is that designation.
#[must_use]
pub fn authorize(request: &Request<'_>, needed: Designation) -> ActionVerdict {
    request.policy.authorize_action(&ActionContext {
        action: ACTION,
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
        require_designation: (needed == Designation::SecurityApprover)
            .then_some(Designation::SecurityApprover),
        step_up_done: false,
    })
}
