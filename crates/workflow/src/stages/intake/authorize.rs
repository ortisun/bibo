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
    Actor, ActorKind, Allowlist, AuthorityDenial, AuthorityPolicy, RepositoryIdentity,
};
use factory_domain::policy::decision::{Designation, GithubUserId};
use factory_domain::values::Timestamp;
use factory_ports::githost::{AccountType, LabelApplication};

/// Who applied a label, as the code host reports it now: the numeric id, the login (display only)
/// and the kind of account. Only a person's account can hold a designation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Labeller<'a> {
    /// The immutable numeric id.
    pub id: u64,
    /// The login at the time of the call. Display only.
    pub login: &'a str,
    /// What kind of account the code host says it is.
    pub account: AccountType,
}

impl<'a> Labeller<'a> {
    /// The person named by an application of a label.
    #[must_use]
    pub fn of(application: &'a LabelApplication) -> Self {
        Self {
            id: application.actor.id,
            login: application.actor.login.as_str(),
            account: application.actor_type,
        }
    }

    /// The kind the authority policy judges. A person's account is a user; every other kind of
    /// account is not one, whatever its numeric id is and whether the allowlist lists it, and the
    /// policy refuses it as not human.
    #[must_use]
    pub const fn kind(&self) -> ActorKind {
        match self.account {
            AccountType::User => ActorKind::User,
            AccountType::Bot => ActorKind::Bot,
            AccountType::Organization | AccountType::Other => ActorKind::App,
        }
    }
}

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
/// `labelled_by` is who applied the label, as the code host reports it now, or `None` when the
/// label is not on the issue. The login is carried for display only; an account that is not a
/// person's is refused as not human.
#[must_use]
pub fn authorize(
    policy: &AuthorityPolicy,
    allowlist: &Allowlist,
    tenant: TenantId,
    repository: &str,
    labelled_by: Option<Labeller<'_>>,
    now: &Timestamp,
) -> Authorization {
    // The requester is judged by the name: the webhook and the API asked with the id before a job
    // reached this stage, so the stage is the second, conjunctive check (finding RH-3).
    authorize_designation(
        Designation::Requester,
        policy,
        allowlist,
        tenant,
        &RepositoryIdentity::by_name_only(repository),
        labelled_by,
        now,
    )
}

/// Decides whether the person who applied a label holds `designation` on the allowlist: by numeric
/// id, not narrowed away from `repository`, not expired, a human. The same rule as [`authorize`],
/// which asks it for the `requester` designation; the design gate asks it for the designation
/// that approves a design.
///
/// `repository` is how the caller knows the repository. The design gate holds the registered row
/// and asks with [`RepositoryIdentity::registered`], so an entry that lists GitHub's numeric id
/// follows the repository through a rename or a transfer and does not reach a new repository
/// under the old name (finding RH-3); an entry that lists a name only is judged by the registered
/// name.
///
/// `labelled_by` is who applied the label, as the code host reports it now, or `None` when the
/// label is not on the issue.
#[must_use]
pub fn authorize_designation(
    designation: Designation,
    policy: &AuthorityPolicy,
    allowlist: &Allowlist,
    tenant: TenantId,
    repository: &RepositoryIdentity<'_>,
    labelled_by: Option<Labeller<'_>>,
    now: &Timestamp,
) -> Authorization {
    let version = allowlist.version_hash().to_owned();
    let Some(Labeller { id, login, .. }) = labelled_by else {
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
        kind: labelled_by.map_or(ActorKind::App, |who| who.kind()),
        github_permission: None,
        author_association: None,
    };
    match policy.designations_for(allowlist, &tenant, repository, &actor, now) {
        Ok(held) if held.contains(&designation) => Authorization::Authorized {
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
