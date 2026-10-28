//! Who may start work: the requester, found by NUMERIC id on the named allowlist.
//!
//! The person who applied the factory label must hold the `requester` designation. The key is the
//! immutable numeric GitHub id. A login is shown in the audit record and decides nothing, and so
//! do the repository permission and the `author_association` of the payload. The rule is the one
//! of `AuthorityPolicy::designations`, which this module calls and does not repeat.
//!
//! The reply to the person must not say which check failed, or the reply is an oracle for the
//! allowlist. Every refusal therefore carries the same [`NOTICE`], and the reason goes to the
//! audit record only.

use factory_domain::ids::TenantId;
use factory_domain::policy::authority::{
    Actor, ActorKind, Allowlist, AuthorityDenial, AuthorityPolicy,
};
use factory_domain::policy::decision::{Designation, GithubUserId};
use factory_domain::values::Timestamp;

/// The one explanation a refused person gets, whatever the reason. It names no check, no list and
/// no person, and it says what to do next.
pub const NOTICE: &str = "The factory did not start work on this request. It starts work only when a person it knows applies its label to an issue. If you think this is a mistake, ask an operator of the factory.";

/// Why a requester was refused. The set is closed. It is for the audit record, never for the
/// reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenialReason {
    /// The label is not on the issue, so nobody asked.
    NoLabel,
    /// The numeric id is not on the allowlist, or is on it without the `requester` designation.
    NotAllowed,
    /// The entry on the allowlist has expired.
    EntryExpired,
    /// The entry is narrowed to other repositories.
    RepositoryNotListed,
    /// The account is not a human user.
    NotHuman,
    /// The policy's deny-only permission condition is on and the account does not meet it.
    PermissionBelowCondition,
    /// The numeric id is not a valid GitHub id.
    InvalidId,
}

/// The decision on one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorization {
    /// The person who applied the label may ask.
    Authorized {
        /// The numeric id.
        actor: u64,
        /// The version hash of the allowlist that said so, for the audit record.
        allowlist_version: String,
    },
    /// Refused.
    Denied {
        /// The numeric id, when the label had an actor.
        actor: Option<u64>,
        /// The version hash of the allowlist that was read.
        allowlist_version: String,
        /// Why. Audit only.
        reason: DenialReason,
    },
}

impl Authorization {
    /// True when the request may go on.
    #[must_use]
    pub const fn is_authorized(&self) -> bool {
        matches!(self, Self::Authorized { .. })
    }

    /// What to tell the person: the same text for every refusal, and nothing for a grant.
    #[must_use]
    pub const fn notice(&self) -> Option<&'static str> {
        match self {
            Self::Authorized { .. } => None,
            Self::Denied { .. } => Some(NOTICE),
        }
    }
}

/// Decides whether the person who applied the label may ask the factory to work.
///
/// `labelled_by` is the numeric id and the login of that person, as the code host reports them
/// now, or `None` when the label is not on the issue. The login is carried for display only.
#[must_use]
pub fn authorize(
    policy: &AuthorityPolicy,
    allowlist: &Allowlist,
    tenant: TenantId,
    repository: &str,
    labelled_by: Option<(u64, &str)>,
    now: &Timestamp,
) -> Authorization {
    let version = allowlist.version_hash().to_owned();
    let Some((id, login)) = labelled_by else {
        return Authorization::Denied {
            actor: None,
            allowlist_version: version,
            reason: DenialReason::NoLabel,
        };
    };
    let Some(numeric) = GithubUserId::new(id) else {
        return Authorization::Denied {
            actor: Some(id),
            allowlist_version: version,
            reason: DenialReason::InvalidId,
        };
    };
    let actor = Actor {
        github_user_id: numeric,
        login,
        kind: ActorKind::User,
        github_permission: None,
        author_association: None,
    };
    match policy.designations(allowlist, &tenant, repository, &actor, now) {
        Ok(held) if held.contains(&Designation::Requester) => Authorization::Authorized {
            actor: id,
            allowlist_version: version,
        },
        Ok(_) => Authorization::Denied {
            actor: Some(id),
            allowlist_version: version,
            reason: DenialReason::NotAllowed,
        },
        Err(denial) => Authorization::Denied {
            actor: Some(id),
            allowlist_version: version,
            reason: match denial {
                AuthorityDenial::NotHuman => DenialReason::NotHuman,
                AuthorityDenial::NotOnAllowlist => DenialReason::NotAllowed,
                AuthorityDenial::EntryExpired => DenialReason::EntryExpired,
                AuthorityDenial::RepositoryNotListed => DenialReason::RepositoryNotListed,
                AuthorityDenial::GithubPermissionBelowCondition => {
                    DenialReason::PermissionBelowCondition
                }
            },
        },
    }
}
