//! The typed command that a person's decision becomes, whichever channel it came by.
//!
//! The dashboard, the command line and a GitHub comment each have a parser in the composition
//! packages. Each produces an [`ApprovalCommand`] and nothing else, so the rules of this stage
//! (who may, what they must have seen, when it stops counting) are written once. A parser never
//! decides anything: it names the sender by **numeric id**, the verb, the reason and what the
//! person saw, and hands the command over.
//!
//! # The verbs
//!
//! There are seven: `approve`, `reject`, `rework`, `pause`, `resume`, `cancel` and `answer`. There
//! is no verb that merges, marks a pull request ready or deploys, and [`parse_verb`] gives
//! [`VerbParse::Unknown`] for each such word. The caller ignores an unknown verb and audits it.
//!
//! `answer` is not a decision of this stage: it answers the questions of a stage run that waits for
//! a person (the specification stage's clarification, `S13`), and the worker gives it to the
//! engine as `Decision::Answer`. It shares the grammar, the API and the action table with the other
//! six so that it is authorized, recorded and applied the same way; the approval service refuses
//! it ([`super::judge`]), and the comment channel does not read it.

use factory_domain::ids::{CausationId, JobId, StageRunId, TenantId};
use factory_domain::policy::authority::ActorKind;
use factory_domain::values::{GitSha, Sha256Digest};
use factory_domain::vocabulary::StageKind;
use factory_ports::githost::{ActorLogin, CommentRef};
use factory_ports::store::ApprovalChannel;

/// What a person can decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verb {
    /// The pull request is good as it stands. Bound to the head, tree, base and evidence seen.
    Approve,
    /// The job ends as rejected.
    Reject,
    /// The work goes back to an earlier stage (limited by the table of human rework routes).
    Rework,
    /// Stops new leases.
    Pause,
    /// Lets a paused job go on.
    Resume,
    /// Cancels the job.
    Cancel,
    /// Answers the questions of a stage run that waits for a person. The text is untrusted and
    /// becomes a new input of that stage run.
    Answer,
}

impl Verb {
    /// Every verb.
    pub const ALL: [Verb; 7] = [
        Self::Approve,
        Self::Reject,
        Self::Rework,
        Self::Pause,
        Self::Resume,
        Self::Cancel,
        Self::Answer,
    ];

    /// The word a person types.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Rework => "rework",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Cancel => "cancel",
            Self::Answer => "answer",
        }
    }

    /// The row of the action table (`policies/approval.yaml`) that authorizes the verb.
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Approve => "approve_pr",
            Self::Reject | Self::Rework => "reject_or_request_rework",
            Self::Pause | Self::Resume => "pause_or_resume_job",
            Self::Cancel => "cancel_job",
            Self::Answer => ANSWER_ACTION,
        }
    }
}

/// The row of the action table that authorizes an answer to a waiting stage run. It names the
/// designations the engine lets answer (`Decision::Answer`): the requester of the job, an operator,
/// an approver or an organization administrator. The engine also checks that a person who answers
/// as a requester is the requester of that job, which an allowlist cannot say.
pub const ANSWER_ACTION: &str = "answer_question";

/// What a word is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbParse {
    /// One of the seven.
    Known(Verb),
    /// Anything else, `merge`, `deploy`, `ready` and `undraft` included. The command is ignored
    /// and audited.
    Unknown,
}

/// Reads the verb of a command. The match is exact and lower case, as the policy writes the verbs.
#[must_use]
pub fn parse_verb(word: &str) -> VerbParse {
    Verb::ALL
        .into_iter()
        .find(|verb| verb.as_str() == word)
        .map_or(VerbParse::Unknown, VerbParse::Known)
}

/// What the person saw when they decided. An approval is bound to all of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// The head of the pull request.
    pub pr_head: GitSha,
    /// The git tree of that head.
    pub tree: GitSha,
    /// The base commit.
    pub base: GitSha,
    /// The hash of the evidence manifest.
    pub manifest: Sha256Digest,
    /// The version of the frozen specification.
    pub spec_version: u32,
    /// The hash of the last ledger entry: the evidence digest.
    pub ledger_head: Sha256Digest,
}

/// The comment a command came from, as the parser read it. The service fetches the comment again
/// and compares: a comment that was edited after the command was read is not a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentEvidence {
    /// Which comment.
    pub comment: CommentRef,
    /// The hash of its body as the parser read it.
    pub body_sha256: Sha256Digest,
}

/// Who sent the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sender {
    /// The immutable numeric id. The only thing authority is looked up by.
    pub id: u64,
    /// The login, for the audit log only.
    pub login: ActorLogin,
    /// A person, a bot or an App.
    pub kind: ActorKind,
}

/// A decision, ready to be judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalCommand {
    /// Identifies this request. A command that arrives twice with the same id is applied once.
    pub id: CausationId,
    /// The tenant.
    pub tenant: TenantId,
    /// The job.
    pub job: JobId,
    /// The `APPROVAL` stage run the decision is for.
    pub stage_run: StageRunId,
    /// What is decided.
    pub verb: Verb,
    /// Who decided.
    pub sender: Sender,
    /// Where the decision was made.
    pub channel: ApprovalChannel,
    /// Why, in the person's words. Untrusted text, 1 to 2000 bytes.
    pub reason: String,
    /// What the person saw. Required for `approve`.
    pub seen: Option<Seen>,
    /// Every open warning of the rule `translation-unfaithful` has a recorded decision of this
    /// person. The API records the decisions and sets this.
    pub warnings_decided: bool,
    /// Where the work goes back to. Required for `rework`.
    pub rework_target: Option<StageKind>,
    /// When the person asked and the confirmation word they sent (ADR 0021). The approval of a
    /// high or critical pull request by the requester alone needs both; `None` elsewhere.
    pub solo: Option<crate::commands::SoloRequest>,
    /// The comment, for the channel `GithubComment`.
    pub comment: Option<CommentEvidence>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seven_verbs_are_known_and_nothing_else_is() {
        for verb in Verb::ALL {
            assert_eq!(parse_verb(verb.as_str()), VerbParse::Known(verb));
        }
        for word in [
            "merge",
            "deploy",
            "ready",
            "undraft",
            "squash",
            "release",
            "Approve",
            "APPROVE",
            "",
            " approve",
            "approve ",
            "approve\n",
        ] {
            assert_eq!(parse_verb(word), VerbParse::Unknown, "{word:?}");
        }
    }

    #[test]
    fn every_verb_is_authorized_by_a_row_of_the_action_table() {
        let rows = [
            "approve_pr",
            "reject_or_request_rework",
            "pause_or_resume_job",
            "cancel_job",
            "answer_question",
        ];
        for verb in Verb::ALL {
            assert!(rows.contains(&verb.action()), "{verb:?}");
        }
    }
}
