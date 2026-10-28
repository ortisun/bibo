//! The rules of a decision, as a pure function.
//!
//! [`judge`] takes a command and the facts that were read just now, and answers either
//! "accepted, with the record to keep" or "refused, for this reason". It reads no clock, no port
//! and no file: the service gathers the facts and applies the answer.
//!
//! # The order of the checks
//!
//! The order is part of the rules, because the first refusal is the only one anybody learns of.
//!
//! 1. **Is it a command?** A command that came from a GitHub comment is checked against the
//!    comment as it is now: the same comment, written by the sender, never edited, with the body
//!    the parser read. A comment edited after the parser read it is not a command.
//! 2. **May the sender do it?** The policy engine decides from the allowlist by **numeric id**,
//!    the designation the action names, the autonomy level and separation of duties. A refusal
//!    here is never explained to the sender (no oracle for outsiders).
//! 3. **For an approval: is it about what is true now?** The person must have seen the binding in
//!    the request, and the binding must still hold: the pull request is open and a draft, its
//!    head, tree and base are the ones seen, the evidence has not moved since they looked, no
//!    value the gate reports are bound to has changed, the request has not expired, every gate is
//!    clear and every translation warning has a recorded decision.

use factory_domain::ids::TenantId;
use factory_domain::policy::PolicyEngine;
use factory_domain::policy::authority::{
    ActionContext, ActionDenialReason, ActionVerdict, Actor, Allowlist, AutonomyLevel, ChangeFacts,
};
use factory_domain::policy::decision::{AuthorizedApproval, GithubUserId};
use factory_domain::values::{GitSha, Sha256Digest, Timestamp};
use factory_ports::githost::Comment;
use factory_ports::store::{ApprovalBinding, ApprovalChannel};

use super::command::{ApprovalCommand, Verb};
use super::request::ApprovalRequest;

/// What is true now, read by the service just before it judged.
#[derive(Debug, Clone)]
pub struct Live<'a> {
    /// The time of the decision, from the clock port.
    pub now: Timestamp,
    /// The pull request is open.
    pub pr_open: bool,
    /// The pull request is a draft.
    pub pr_draft: bool,
    /// The commit the pull request points at.
    pub pr_head: &'a GitSha,
    /// The git tree of that commit.
    pub tree: &'a GitSha,
    /// The commit the base branch points at.
    pub base_tip: &'a GitSha,
    /// The hash of the last ledger entry.
    pub ledger_head: &'a Sha256Digest,
    /// The bound values that differ from the evidence binding (see `delivery::binding`).
    pub drift: &'a [&'static str],
}

/// Everything a judgement reads besides the command.
#[derive(Debug, Clone)]
pub struct Context<'a> {
    /// What the person was asked to decide.
    pub request: &'a ApprovalRequest,
    /// What is true now.
    pub live: Live<'a>,
    /// The policy.
    pub policy: &'a PolicyEngine,
    /// The allowlist in force now.
    pub allowlist: &'a Allowlist,
    /// The level the job runs at.
    pub level: AutonomyLevel,
    /// The tenant.
    pub tenant: &'a TenantId,
    /// The comment as it is now, for the channel `GithubComment`.
    pub comment: Option<&'a Comment>,
}

/// Why the text of a comment is not a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotACommand {
    /// The channel is a comment and the command names none, or the host returned none.
    CommentMissing,
    /// The comment was written by someone else than the sender.
    CommentAuthor,
    /// The comment is not the one the parser read.
    CommentOther,
    /// The comment was edited. An edit never makes a command (`accept_event: issue_comment.created`).
    CommentEdited,
    /// The body is not the body the parser read.
    CommentChanged,
}

/// Why a decision is refused. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The text is not a command. Ignored and audited, with no reply.
    NotACommand(NotACommand),
    /// The sender may not do this. Ignored and audited, with no reply.
    Unauthorized(ActionDenialReason),
    /// An approval names nothing the person saw.
    NotBound,
    /// What the person saw is not what the request holds (the named part differs).
    StaleBinding(&'static str),
    /// The head of the pull request moved after the person looked.
    HeadMoved,
    /// The base branch moved after the person looked.
    BaseMoved,
    /// The tree of the head is not the one seen.
    TreeChanged,
    /// Evidence was added to the ledger after the person looked.
    EvidenceMoved,
    /// A value the gate reports are bound to changed (the names).
    EvidenceDrift(Vec<&'static str>),
    /// The request is older than the approval may count for.
    Expired,
    /// The pull request is not open.
    NotOpen,
    /// The pull request is not a draft.
    NotDraft,
    /// A gate failed or was blocked and nobody decided about it.
    GatesNotClear,
    /// A warning of the rule `translation-unfaithful` has no recorded decision.
    TranslationWarningsUndecided,
    /// A rework needs the stage to go back to.
    MissingTarget,
    /// A rejection needs a reason.
    MissingReason,
    /// This person already recorded this decision for this head.
    AlreadyDecided,
}

impl Refusal {
    /// A short code for the audit record.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotACommand(_) => "not_a_command",
            Self::Unauthorized(ActionDenialReason::SelfApproval)
            | Self::Unauthorized(ActionDenialReason::Authority(
                factory_domain::policy::authority::AuthorityDenial::NotHuman,
            )) => "ineligible_approver",
            Self::Unauthorized(_) => "not_authorized",
            Self::NotBound => "not_bound",
            Self::StaleBinding(_) => "stale_binding",
            Self::HeadMoved => "new_commit",
            Self::BaseMoved => "base_moved",
            Self::TreeChanged => "tree_changed",
            Self::EvidenceMoved => "evidence_moved",
            Self::EvidenceDrift(_) => "evidence_drift",
            Self::Expired => "expired",
            Self::NotOpen => "not_open",
            Self::NotDraft => "not_draft",
            Self::GatesNotClear => "gates_not_clear",
            Self::TranslationWarningsUndecided => "translation_warnings_undecided",
            Self::MissingTarget => "missing_target",
            Self::MissingReason => "missing_reason",
            Self::AlreadyDecided => "already_decided",
        }
    }

    /// True when the sender may be told why. A command that is not a command, and a sender who may
    /// not decide, learn nothing: a reply would tell an outsider which commands exist and who is
    /// on the list.
    #[must_use]
    pub fn may_reply(&self) -> bool {
        !matches!(self, Self::NotACommand(_) | Self::Unauthorized(_))
    }
}

/// A decision that passed every check, with what the service records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// The proof from the policy engine: the numeric id, the designation, the allowlist version
    /// and the rule.
    pub authorization: AuthorizedApproval,
    /// The binding, for an approval.
    pub binding: Option<ApprovalBinding>,
}

fn comment_checks(cmd: &ApprovalCommand, cx: &Context<'_>) -> Result<(), NotACommand> {
    if cmd.channel != ApprovalChannel::GithubComment {
        return Ok(());
    }
    let (Some(evidence), Some(live)) = (&cmd.comment, cx.comment) else {
        return Err(NotACommand::CommentMissing);
    };
    if live.reference != evidence.comment {
        return Err(NotACommand::CommentOther);
    }
    if live.author.id != cmd.sender.id {
        return Err(NotACommand::CommentAuthor);
    }
    if live.edited_at.is_some() {
        return Err(NotACommand::CommentEdited);
    }
    if Sha256Digest::of(live.body.as_bytes()) != evidence.body_sha256 {
        return Err(NotACommand::CommentChanged);
    }
    Ok(())
}

/// Judges a command.
///
/// # Errors
/// The [`Refusal`] for the first check that fails.
pub fn judge(cmd: &ApprovalCommand, cx: &Context<'_>) -> Result<Accepted, Refusal> {
    comment_checks(cmd, cx).map_err(Refusal::NotACommand)?;

    let Some(sender_id) = GithubUserId::new(cmd.sender.id) else {
        return Err(Refusal::Unauthorized(ActionDenialReason::Authority(
            factory_domain::policy::authority::AuthorityDenial::NotOnAllowlist,
        )));
    };
    let request = cx.request;
    let actor = Actor {
        github_user_id: sender_id,
        login: cmd.sender.login.as_str(),
        kind: cmd.sender.kind,
        github_permission: None,
        author_association: None,
    };
    let verdict = cx.policy.authority.authorize_action(&ActionContext {
        action: cmd.verb.action(),
        level: cx.level,
        tenant: cx.tenant,
        repository: &request.repository,
        actor: &actor,
        allowlist: cx.allowlist,
        now: &cx.live.now,
        requester: GithubUserId::new(request.requester),
        change: ChangeFacts {
            risk_tier: request.tier,
            protected_path_change: request.protected_path_change,
            sensitive_file_change: request.sensitive_file_change,
            new_dependency: request.new_dependency,
        },
        require_designation: None,
        step_up_done: false,
    });
    let authorization = match verdict {
        ActionVerdict::Authorized(proof) => proof,
        ActionVerdict::Denied(denial) => return Err(Refusal::Unauthorized(denial.reason)),
        // The action needs no human at this level. A person's command is not an input then.
        ActionVerdict::NoHumanNeeded { .. } => {
            return Err(Refusal::Unauthorized(ActionDenialReason::ForbiddenAtLevel));
        }
    };

    match cmd.verb {
        Verb::Approve => approve(cmd, cx, authorization),
        Verb::Reject => {
            if cmd.reason.trim().is_empty() {
                return Err(Refusal::MissingReason);
            }
            Ok(Accepted {
                authorization,
                binding: None,
            })
        }
        Verb::Rework => {
            if cmd.rework_target.is_none() {
                return Err(Refusal::MissingTarget);
            }
            Ok(Accepted {
                authorization,
                binding: None,
            })
        }
        Verb::Pause | Verb::Resume | Verb::Cancel => Ok(Accepted {
            authorization,
            binding: None,
        }),
    }
}

fn approve(
    cmd: &ApprovalCommand,
    cx: &Context<'_>,
    authorization: AuthorizedApproval,
) -> Result<Accepted, Refusal> {
    let request = cx.request;
    let live = &cx.live;
    let seen = cmd.seen.as_ref().ok_or(Refusal::NotBound)?;

    // What the person saw must be what the request holds.
    let stale = [
        ("pr_head", seen.pr_head == request.pr_head),
        ("tree", seen.tree == request.tree),
        ("base", seen.base == request.base),
        ("manifest", seen.manifest == request.manifest),
        ("spec_version", seen.spec_version == request.spec_version),
    ]
    .into_iter()
    .find(|(_, equal)| !equal);
    if let Some((part, _)) = stale {
        return Err(Refusal::StaleBinding(part));
    }

    // The request counts for 72 hours.
    match request.expires_at() {
        Some(end) if live.now < end => {}
        _ => return Err(Refusal::Expired),
    }
    if !live.pr_open {
        return Err(Refusal::NotOpen);
    }
    if !live.pr_draft {
        return Err(Refusal::NotDraft);
    }

    // The world must still be what they saw.
    if live.pr_head != &seen.pr_head {
        return Err(Refusal::HeadMoved);
    }
    if live.base_tip != &seen.base {
        return Err(Refusal::BaseMoved);
    }
    if live.tree != &seen.tree {
        return Err(Refusal::TreeChanged);
    }
    if live.ledger_head != &seen.ledger_head {
        return Err(Refusal::EvidenceMoved);
    }
    if !live.drift.is_empty() {
        return Err(Refusal::EvidenceDrift(live.drift.to_vec()));
    }
    if !request.gates_clear {
        return Err(Refusal::GatesNotClear);
    }
    if request.open_translation_warnings > 0 && !cmd.warnings_decided {
        return Err(Refusal::TranslationWarningsUndecided);
    }
    Ok(Accepted {
        authorization,
        binding: Some(ApprovalBinding {
            pr_head: seen.pr_head.clone(),
            tree: seen.tree.clone(),
            base: seen.base.clone(),
            evidence_manifest: seen.manifest.clone(),
            spec_version: seen.spec_version,
        }),
    })
}
