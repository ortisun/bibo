//! The parsers that turn a person's decision into an [`ApprovalCommand`], whichever channel it
//! came by: a GitHub comment, the command line, or a dashboard form.
//!
//! These are pure functions of text. They hold no HTTP, no process arguments and no identity:
//! the API reads the request and the webhook sender, the CLI reads `argv`, and each hands the text
//! to the function for its channel. A parser **never decides anything**. It reads the verb, the
//! reason, what the person says they saw and where work should go back to, and it refuses what is
//! malformed. Who may do it, whether the head is still current and when the decision stops
//! counting are the approval stage's rules (`factory_workflow::stages::approval::judge`).
//!
//! # The grammar
//!
//! One line, the same words in every channel:
//!
//! ```text
//! /factory <verb> [head=<40 or 64 hex>] [evidence=<sha256:...>] [target=<STAGE_KIND>] [reason text]
//! ```
//!
//! * The comment parser reads only the **first line** of a body and only if it starts with
//!   `/factory ` (a body that does not is not a command: `Ok(None)`). A verb that is not one of
//!   the six is `Err(UnknownVerb)`, which the caller audits and ignores. `merge`, `deploy`,
//!   `ready` and `undraft` are all unknown.
//! * The command line parser takes the words after `factory` as separate arguments and joins what
//!   is left as the reason, so the grammar is the same.
//! * The dashboard form is key and value pairs: `verb`, `head`, `evidence`, `target`, `reason`.
//!
//! `key=value` words come before the reason. The first word that is not a `key=value` pair of a
//! known key starts the reason, so a reason may contain `=` later. A key given twice is an error.
//!
//! # What "seen" is
//!
//! An approval is bound to the head of the pull request, its tree, the base, the evidence
//! manifest, the specification version and the last ledger entry. A person types two of those:
//! the head (`head=`) and the evidence digest (`evidence=`, the hash of the last ledger entry they
//! read). The tree, the base, the manifest and the version are determined by the head and are
//! taken from the stored approval request that the head belongs to ([`ParsedDecision::into_command`]).

use factory_domain::ids::{CausationId, JobId, StageRunId, TenantId};
use factory_domain::values::{GitSha, Sha256Digest};
use factory_domain::vocabulary::StageKind;
use factory_ports::store::ApprovalChannel;
use factory_workflow::stages::approval::{
    ApprovalCommand, ApprovalRequest, CommentEvidence, Seen, Sender, Verb, VerbParse, parse_verb,
};

/// The longest reason a decision may carry, in bytes (the store's limit).
pub const MAX_REASON_BYTES: usize = 2000;

/// The word that opens a command in a comment.
pub const COMMENT_PREFIX: &str = "/factory ";

/// Why a decision could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    /// The verb is not one of the six.
    #[error("{0:?} is not a decision the factory takes")]
    UnknownVerb(String),
    /// There is no verb after the prefix.
    #[error("the command has no verb")]
    NoVerb,
    /// A `key=value` word has a value that is not valid for its key.
    #[error("the value of {0} is not valid")]
    BadValue(&'static str),
    /// A key was given twice.
    #[error("{0} was given twice")]
    Repeated(&'static str),
    /// The reason is empty where the verb needs one, or longer than the store allows.
    #[error("the reason must be 1 to {MAX_REASON_BYTES} bytes")]
    Reason,
    /// A verb that needs something it was not given.
    #[error("{0} needs {1}")]
    Missing(&'static str, &'static str),
}

/// A decision as a person wrote it, before the context is added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDecision {
    /// What is decided.
    pub verb: Verb,
    /// Why, in the person's words. Untrusted text.
    pub reason: String,
    /// The head the person says they saw.
    pub head: Option<GitSha>,
    /// The ledger digest the person says they read.
    pub evidence: Option<Sha256Digest>,
    /// Where the work goes back to, for `rework`.
    pub target: Option<StageKind>,
}

/// Who and where, added by the caller to a parsed decision.
#[derive(Debug, Clone)]
pub struct CommandContext {
    /// Identifies the request, so a repeat is applied once.
    pub id: CausationId,
    /// The tenant.
    pub tenant: TenantId,
    /// The job.
    pub job: JobId,
    /// The approval stage run.
    pub stage_run: StageRunId,
    /// Who sent it, by numeric id.
    pub sender: Sender,
    /// Where it was made.
    pub channel: ApprovalChannel,
    /// The comment, for the comment channel.
    pub comment: Option<CommentEvidence>,
    /// Every open translation warning has a recorded decision of this person.
    pub warnings_decided: bool,
}

impl ParsedDecision {
    /// The command, with what the person saw taken from the stored request.
    ///
    /// For `approve` the person must have given a head and an evidence digest; the other fields of
    /// [`Seen`] come from `request`, which is the request that the head belongs to. The stage
    /// compares them with the current ones and refuses a stale decision.
    ///
    /// # Errors
    /// [`CommandError::Missing`] when `approve` lacks the head or the evidence digest, or
    /// `rework` lacks its target.
    pub fn into_command(
        self,
        context: CommandContext,
        request: Option<&ApprovalRequest>,
    ) -> Result<ApprovalCommand, CommandError> {
        let seen = match (self.verb, request) {
            (Verb::Approve, Some(request)) => {
                let head = self
                    .head
                    .clone()
                    .ok_or(CommandError::Missing("approve", "head=<commit>"))?;
                let ledger_head = self
                    .evidence
                    .clone()
                    .ok_or(CommandError::Missing("approve", "evidence=<digest>"))?;
                Some(Seen {
                    pr_head: head,
                    tree: request.tree.clone(),
                    base: request.base.clone(),
                    manifest: request.manifest.clone(),
                    spec_version: request.spec_version,
                    ledger_head,
                })
            }
            (Verb::Approve, None) => {
                return Err(CommandError::Missing("approve", "the stored request"));
            }
            _ => None,
        };
        if self.verb == Verb::Rework && self.target.is_none() {
            return Err(CommandError::Missing("rework", "target=<STAGE_KIND>"));
        }
        Ok(ApprovalCommand {
            id: context.id,
            tenant: context.tenant,
            job: context.job,
            stage_run: context.stage_run,
            verb: self.verb,
            sender: context.sender,
            channel: context.channel,
            reason: self.reason,
            seen,
            warnings_decided: context.warnings_decided,
            rework_target: self.target,
            comment: context.comment,
        })
    }
}

/// The reason, checked: 1 to [`MAX_REASON_BYTES`] bytes after trimming.
fn reason(words: &[&str]) -> Result<String, CommandError> {
    let text = words.join(" ");
    let text = text.trim();
    if text.is_empty() || text.len() > MAX_REASON_BYTES {
        return Err(CommandError::Reason);
    }
    Ok(text.to_owned())
}

/// Reads the words after the verb: `key=value` pairs, then the reason.
fn read_words(verb: Verb, words: &[&str]) -> Result<ParsedDecision, CommandError> {
    let mut head = None;
    let mut evidence = None;
    let mut target = None;
    let mut taken = 0;
    for word in words {
        let Some((key, value)) = word.split_once('=') else {
            break;
        };
        match key {
            "head" => {
                if head.is_some() {
                    return Err(CommandError::Repeated("head"));
                }
                head = Some(GitSha::parse(value).map_err(|_| CommandError::BadValue("head"))?);
            }
            "evidence" => {
                if evidence.is_some() {
                    return Err(CommandError::Repeated("evidence"));
                }
                evidence = Some(
                    Sha256Digest::parse(value).map_err(|_| CommandError::BadValue("evidence"))?,
                );
            }
            "target" => {
                if target.is_some() {
                    return Err(CommandError::Repeated("target"));
                }
                target =
                    Some(StageKind::parse(value).map_err(|_| CommandError::BadValue("target"))?);
            }
            _ => break,
        }
        taken += 1;
    }
    // Approve may go without a reason; every other verb says why.
    let rest = &words[taken..];
    let reason = match (verb, rest.is_empty()) {
        (Verb::Approve, true) => "approved".to_owned(),
        _ => reason(rest)?,
    };
    Ok(ParsedDecision {
        verb,
        reason,
        head,
        evidence,
        target,
    })
}

fn verb_of(word: &str) -> Result<Verb, CommandError> {
    match parse_verb(word) {
        VerbParse::Known(verb) => Ok(verb),
        VerbParse::Unknown => Err(CommandError::UnknownVerb(word.to_owned())),
    }
}

/// Reads a GitHub comment. `Ok(None)` for a body that is not a command.
///
/// # Errors
/// [`CommandError`] for a command that is malformed or names a verb the factory does not take.
pub fn parse_comment(body: &str) -> Result<Option<ParsedDecision>, CommandError> {
    let first = body.lines().next().unwrap_or("");
    let Some(rest) = first.strip_prefix(COMMENT_PREFIX) else {
        return Ok(None);
    };
    let words: Vec<&str> = rest.split_whitespace().collect();
    let (verb, words) = words.split_first().ok_or(CommandError::NoVerb)?;
    read_words(verb_of(verb)?, words).map(Some)
}

/// Reads the arguments of the command line, the words after `factory`.
///
/// # Errors
/// [`CommandError`].
pub fn parse_cli(args: &[&str]) -> Result<ParsedDecision, CommandError> {
    let (verb, words) = args.split_first().ok_or(CommandError::NoVerb)?;
    read_words(verb_of(verb)?, words)
}

/// Reads a dashboard form: pairs of name and value.
///
/// # Errors
/// [`CommandError`].
pub fn parse_form(fields: &[(&str, &str)]) -> Result<ParsedDecision, CommandError> {
    let get = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.trim())
            .filter(|value| !value.is_empty())
    };
    let verb = verb_of(get("verb").ok_or(CommandError::NoVerb)?)?;
    let head = get("head")
        .map(|value| GitSha::parse(value).map_err(|_| CommandError::BadValue("head")))
        .transpose()?;
    let evidence = get("evidence")
        .map(|value| Sha256Digest::parse(value).map_err(|_| CommandError::BadValue("evidence")))
        .transpose()?;
    let target = get("target")
        .map(|value| StageKind::parse(value).map_err(|_| CommandError::BadValue("target")))
        .transpose()?;
    let reason = match (verb, get("reason")) {
        (Verb::Approve, None) => "approved".to_owned(),
        (_, Some(text)) => reason(&[text])?,
        (_, None) => return Err(CommandError::Reason),
    };
    Ok(ParsedDecision {
        verb,
        reason,
        head,
        evidence,
        target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(letter: char) -> String {
        letter.to_string().repeat(40)
    }

    fn digest() -> String {
        Sha256Digest::of(b"ledger head").as_str().to_owned()
    }

    #[test]
    fn a_comment_that_is_not_a_command_is_not_read() {
        for body in [
            "looks good",
            "",
            "/factory",
            "approve",
            " /factory approve",
            "//factory approve",
        ] {
            assert_eq!(parse_comment(body), Ok(None), "{body:?}");
        }
        assert_eq!(parse_comment("/factory "), Err(CommandError::NoVerb));
    }

    fn context(verb_channel: ApprovalChannel) -> CommandContext {
        use factory_domain::policy::authority::ActorKind;
        use factory_ports::githost::ActorLogin;
        CommandContext {
            id: CausationId::from_uuid(uuid::Uuid::from_u128(1)),
            tenant: TenantId::from_uuid(uuid::Uuid::from_u128(2)),
            job: JobId::from_uuid(uuid::Uuid::from_u128(3)),
            stage_run: StageRunId::from_uuid(uuid::Uuid::from_u128(4)),
            sender: Sender {
                id: 1001,
                login: ActorLogin::new("someone").expect("a login"),
                kind: ActorKind::User,
            },
            channel: verb_channel,
            comment: None,
            warnings_decided: false,
        }
    }

    #[test]
    fn a_command_is_completed_only_when_it_has_what_its_verb_needs() {
        let approve = parse_cli(&["approve"]).expect("reads");
        assert_eq!(
            approve
                .clone()
                .into_command(context(ApprovalChannel::Cli), None),
            Err(CommandError::Missing("approve", "the stored request"))
        );
        let rework = parse_cli(&["rework", "no", "tests"]).expect("reads");
        assert_eq!(
            rework.into_command(context(ApprovalChannel::Cli), None),
            Err(CommandError::Missing("rework", "target=<STAGE_KIND>"))
        );
        let reject = parse_cli(&["reject", "wrong", "approach"]).expect("reads");
        let command = reject
            .into_command(context(ApprovalChannel::Dashboard), None)
            .expect("a reject needs no seen");
        assert_eq!(command.verb, Verb::Reject);
        assert!(command.seen.is_none());
        assert_eq!(command.sender.id, 1001);
    }

    #[test]
    fn only_the_first_line_of_a_comment_is_read() {
        let body = format!(
            "/factory approve head={} evidence={} thanks\n/factory cancel stop everything",
            sha('a'),
            digest()
        );
        let parsed = parse_comment(&body).expect("reads").expect("a command");
        assert_eq!(parsed.verb, Verb::Approve);
        assert_eq!(parsed.reason, "thanks");
        assert_eq!(
            parsed.head.as_ref().map(GitSha::as_str),
            Some(sha('a').as_str())
        );
        assert!(parsed.evidence.is_some());
    }

    #[test]
    fn the_six_verbs_parse_and_nothing_that_merges_does() {
        for verb in Verb::ALL {
            let line = format!("/factory {} because I say so", verb.as_str());
            let parsed = parse_comment(&line).expect("reads").expect("a command");
            assert_eq!(parsed.verb, verb);
        }
        for word in ["merge", "deploy", "ready", "undraft", "Approve", "squash"] {
            let error = parse_comment(&format!("/factory {word} now")).expect_err("refused");
            assert_eq!(error, CommandError::UnknownVerb(word.to_owned()));
        }
    }

    #[test]
    fn a_reason_is_needed_by_every_verb_but_approve_and_is_bounded() {
        assert_eq!(parse_comment("/factory reject"), Err(CommandError::Reason));
        assert_eq!(
            parse_comment("/factory cancel   "),
            Err(CommandError::Reason)
        );
        assert_eq!(
            parse_comment("/factory approve")
                .expect("reads")
                .expect("a command")
                .reason,
            "approved"
        );
        let long = format!("/factory reject {}", "x".repeat(MAX_REASON_BYTES + 1));
        assert_eq!(parse_comment(&long), Err(CommandError::Reason));
        let exact = format!("/factory reject {}", "x".repeat(MAX_REASON_BYTES));
        assert!(parse_comment(&exact).is_ok());
    }

    #[test]
    fn keys_come_first_and_a_bad_value_or_a_repeated_key_is_refused() {
        assert_eq!(
            parse_comment("/factory approve head=zz"),
            Err(CommandError::BadValue("head"))
        );
        assert_eq!(
            parse_comment(&format!(
                "/factory approve head={} head={}",
                sha('a'),
                sha('b')
            )),
            Err(CommandError::Repeated("head"))
        );
        assert_eq!(
            parse_comment("/factory rework target=NOT_A_STAGE no"),
            Err(CommandError::BadValue("target"))
        );
        // The first word that is not a known pair starts the reason, so it may contain `=`.
        let parsed = parse_comment("/factory reject a=b is not a key")
            .expect("reads")
            .expect("a command");
        assert_eq!(parsed.reason, "a=b is not a key");
    }

    #[test]
    fn the_command_line_and_the_form_read_the_same_grammar() {
        let cli = parse_cli(&["rework", "target=IMPLEMENTATION", "tests", "are", "missing"])
            .expect("reads");
        assert_eq!(cli.verb, Verb::Rework);
        assert_eq!(cli.target, Some(StageKind::Implementation));
        assert_eq!(cli.reason, "tests are missing");
        let form = parse_form(&[
            ("verb", "rework"),
            ("target", "IMPLEMENTATION"),
            ("reason", "tests are missing"),
        ])
        .expect("reads");
        assert_eq!(form, cli);
        assert_eq!(parse_cli(&[]), Err(CommandError::NoVerb));
        assert_eq!(parse_form(&[]), Err(CommandError::NoVerb));
        assert_eq!(
            parse_form(&[("verb", "merge"), ("reason", "go")]),
            Err(CommandError::UnknownVerb("merge".to_owned()))
        );
    }
}
