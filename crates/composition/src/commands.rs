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
//!   the seven is `Err(UnknownVerb)`, which the caller audits and ignores. `merge`, `deploy`,
//!   `ready` and `undraft` are all unknown. `answer` is known and refused in a comment
//!   (`Err(NotInComments)`, see below).
//! * The command line parser takes the words after `factory` as separate arguments and joins what
//!   is left as the reason, so the grammar is the same.
//! * The dashboard form is key and value pairs: `verb`, `head`, `evidence`, `target`, `reason`.
//!
//! `key=value` words come before the reason. The first word that is not a `key=value` pair of a
//! known key starts the reason, so a reason may contain `=` later. A key given twice is an error.
//!
//! # The answer to a waiting stage run
//!
//! ```text
//! answer <text>
//! ```
//!
//! `answer` takes no `key=value` word: every word after the verb is the answer, which is untrusted
//! text of 1 to [`MAX_ANSWER_BYTES`] bytes. The stage reads one answer per line `Q-001: ...`, and a
//! text with no such line answers the first question. Words on a command line cannot carry a line
//! break, so a word that starts with a question label (`Q-` and three or more digits, then `:`)
//! starts a new line: `answer Q-001: yes Q-002: no` is the two lines `Q-001: yes` and `Q-002: no`.
//! The dashboard form gives the text as it is, in the field `answer`.
//!
//! **A comment does not take `answer`** (`Err(NotInComments)`). The comment channel reads one line,
//! which cannot hold several answers; what it reads goes to the approval service, which judges
//! pull request approvals and has nothing to do with a stage run that asks; and the text of an
//! answer becomes an input of an agent stage, so it comes only through the authenticated API,
//! where it is recorded under the person's token and the API's keyed word.
//!
//! # The two verbs of a dependency decision
//!
//! `approve-dependency <name> <version> [checksum prefix] <reason>` and `approve-build-code ...` are
//! read by [`parse_dependency_command`], which lives with the gates that wait for them. They are
//! re-exported here so that the API and the command line read them with the one grammar; they are
//! not among the seven verbs and have no [`ParsedDecision`].
//!
//! # What "seen" is
//!
//! An approval is bound to the head of the pull request, its tree, the base, the evidence
//! manifest, the specification version and the last ledger entry. A person types two of those:
//! the head (`head=`) and the evidence digest (`evidence=`, the hash of the last ledger entry they
//! read). The tree, the base, the manifest and the version are determined by the head and are
//! taken from the stored approval request that the head belongs to ([`ParsedDecision::into_command`]).

pub use factory_workflow::gates::supply_chain::command::{
    APPROVE_BUILD_CODE, APPROVE_DEPENDENCY, CommandError as DependencyCommandError,
    DependencyCommand, ParsedLine, parse_dependency_command,
};

use factory_domain::ids::{CausationId, JobId, StageRunId, TenantId};
use factory_domain::values::{GitSha, Sha256Digest};
use factory_domain::vocabulary::StageKind;
use factory_ports::store::ApprovalChannel;
use factory_workflow::stages::approval::{
    ApprovalCommand, ApprovalRequest, CommentEvidence, Seen, Sender, Verb, VerbParse, parse_verb,
};

/// The longest reason a decision may carry, in bytes (the store's limit).
pub const MAX_REASON_BYTES: usize = 2000;

/// The longest answer a decision carries, in bytes. It is what the audit record of the request
/// keeps of a person's text in full (the API cuts a longer reason, and an answer must never be cut),
/// and far below the stage's own bound on one answer (8 KiB).
pub const MAX_ANSWER_BYTES: usize = 900;

/// The word that opens a command in a comment.
pub const COMMENT_PREFIX: &str = "/factory ";

/// Why a decision could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    /// The verb is not one of the seven.
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
    /// The answer is empty, or longer than an answer may be.
    #[error("the answer must be 1 to {MAX_ANSWER_BYTES} bytes")]
    Answer,
    /// The verb is one the comment channel does not take.
    #[error("{0} is not taken in a comment; use the API or the command line")]
    NotInComments(&'static str),
}

/// A decision as a person wrote it, before the context is added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDecision {
    /// What is decided.
    pub verb: Verb,
    /// Why, in the person's words; for `answer`, the answer. Untrusted text.
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

/// True when a word starts a line of an answer: `Q-`, three or more digits, then `:`.
fn starts_a_question_line(word: &str) -> bool {
    let Some(rest) = word.strip_prefix("Q-") else {
        return false;
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    digits >= 3 && rest.as_bytes().get(digits) == Some(&b':')
}

/// An answer, checked: 1 to [`MAX_ANSWER_BYTES`] bytes after trimming.
///
/// # Errors
/// [`CommandError::Answer`].
pub fn checked_answer(text: &str) -> Result<String, CommandError> {
    let text = text.trim();
    if text.is_empty() || text.len() > MAX_ANSWER_BYTES {
        return Err(CommandError::Answer);
    }
    Ok(text.to_owned())
}

/// The words of an answer as one text: joined by spaces, and a word that starts with a question
/// label starts a new line.
fn answer_of(words: &[&str]) -> Result<String, CommandError> {
    let mut text = String::new();
    for word in words {
        if !text.is_empty() {
            text.push(if starts_a_question_line(word) {
                '\n'
            } else {
                ' '
            });
        }
        text.push_str(word);
    }
    checked_answer(&text)
}

/// Reads the words after the verb: `key=value` pairs, then the reason. For `answer`, every word is
/// the answer.
fn read_words(verb: Verb, words: &[&str]) -> Result<ParsedDecision, CommandError> {
    if verb == Verb::Answer {
        return Ok(ParsedDecision {
            verb,
            reason: answer_of(words)?,
            head: None,
            evidence: None,
            target: None,
        });
    }
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
    let verb = verb_of(verb)?;
    if verb == Verb::Answer {
        return Err(CommandError::NotInComments(verb.as_str()));
    }
    read_words(verb, words).map(Some)
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
    if verb == Verb::Answer {
        // The text as it is given, line breaks and all; no other word means anything to it.
        let text = fields
            .iter()
            .find(|(key, _)| *key == "answer")
            .map_or("", |(_, value)| *value);
        return Ok(ParsedDecision {
            verb,
            reason: checked_answer(text)?,
            head: None,
            evidence: None,
            target: None,
        });
    }
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
    fn an_answer_is_its_text_and_each_question_label_starts_a_line() {
        let parsed =
            parse_cli(&["answer", "Q-001:", "yes,", "add", "it", "Q-002:", "no"]).expect("reads");
        assert_eq!(parsed.verb, Verb::Answer);
        assert_eq!(parsed.reason, "Q-001: yes, add it\nQ-002: no");
        assert!(parsed.head.is_none() && parsed.evidence.is_none() && parsed.target.is_none());
        // No key is read: a word with `=` is part of the answer, and so is a label in the middle
        // of a word.
        let parsed = parse_cli(&["answer", "target=IMPLEMENTATION", "is", "fine", "xQ-003:"])
            .expect("reads");
        assert_eq!(parsed.reason, "target=IMPLEMENTATION is fine xQ-003:");
        assert!(parsed.target.is_none());
        // A text with no label is one line: the stage reads it as the answer to Q-001.
        let parsed = parse_cli(&["answer", "use", "the", "JSON", "flag"]).expect("reads");
        assert_eq!(parsed.reason, "use the JSON flag");
        // Two digits are not a label.
        let parsed = parse_cli(&["answer", "a", "Q-01:", "b"]).expect("reads");
        assert_eq!(parsed.reason, "a Q-01: b");
    }

    #[test]
    fn an_empty_or_too_long_answer_is_refused() {
        assert_eq!(parse_cli(&["answer"]), Err(CommandError::Answer));
        assert_eq!(
            parse_cli(&["answer", "  ", "\t"]),
            Err(CommandError::Answer)
        );
        let long = "x".repeat(MAX_ANSWER_BYTES + 1);
        assert_eq!(parse_cli(&["answer", &long]), Err(CommandError::Answer));
        let exact = "x".repeat(MAX_ANSWER_BYTES);
        assert_eq!(parse_cli(&["answer", &exact]).expect("reads").reason, exact);
        assert_eq!(parse_form(&[("verb", "answer")]), Err(CommandError::Answer));
        assert_eq!(
            parse_form(&[("verb", "answer"), ("answer", " \n ")]),
            Err(CommandError::Answer)
        );
        // The reason of another verb is not an answer.
        assert_eq!(
            parse_form(&[("verb", "answer"), ("reason", "yes")]),
            Err(CommandError::Answer)
        );
    }

    #[test]
    fn the_form_keeps_the_line_breaks_of_an_answer() {
        let parsed = parse_form(&[("verb", "answer"), ("answer", "Q-001: yes\nQ-002: no\n")])
            .expect("reads");
        assert_eq!(parsed.verb, Verb::Answer);
        assert_eq!(parsed.reason, "Q-001: yes\nQ-002: no");
    }

    #[test]
    fn a_comment_does_not_take_an_answer() {
        assert_eq!(
            parse_comment("/factory answer Q-001: yes"),
            Err(CommandError::NotInComments("answer"))
        );
        assert_eq!(
            parse_comment("/factory answer"),
            Err(CommandError::NotInComments("answer"))
        );
    }

    #[test]
    fn the_verbs_parse_and_nothing_that_merges_does() {
        for verb in Verb::ALL.into_iter().filter(|verb| *verb != Verb::Answer) {
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
