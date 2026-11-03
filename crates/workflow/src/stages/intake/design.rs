//! The design gate: an issue on the design track starts work only when its design is approved, and
//! approved by a person whom the allowlist knows as an approver.
//!
//! # The rule
//!
//! Intake reads the labels of the issue from the code host now (the webhook payload is not used)
//! and classifies them with [`DesignGate::classify`]:
//!
//! * **No design label, and none ever applied.** A small, clear change. Nothing here touches it.
//! * **No design label now, but one was applied and taken off.** The track is sticky: the issue is
//!   on it, and is refused like any issue of the track until an approver applies `design: approved`.
//!   Taking the label away is not a way off the track. The events of the issue say so, and if they
//!   cannot be read to the end the attempt fails, which is a refusal and never a pass.
//! * **Any design label and no `design: approved`.** Refused, with the block code
//!   `DESIGN_NOT_APPROVED`.
//! * **`design: approved` together with another design label.** Refused: a reopened design whose
//!   old label has not been cleaned up is not an approved design.
//! * **`design: approved` alone.** The person who applied it must hold the designation that the
//!   policy names (`intake_requirements.design_approved_by`, `approver` by default), found by
//!   numeric id on the protected allowlist, not narrowed away from this repository, not expired,
//!   and a person's account (not a bot or an organization, even if its id is listed). A label
//!   applied by anybody else is refused. GitHub gives triage rights to many
//!   people, and the Action only checks that a design document exists, so the label alone proves
//!   nothing about who decided.
//!
//! # The text must be the issue's text (DG-3)
//!
//! Besides the labels, the gate compares the text the job carries with the text the live issue
//! gives now: the title, a blank line and the body, through the same secret redactor that stores
//! the text of a webhook job. The product owner decided on 2026-11-02 that the text the factory
//! acts on must be the issue's, or the job is refused. A webhook job takes its text from the issue,
//! so the two are the same by construction. A job made through the API or the command line carries
//! the words its caller typed; they must be the issue's words, and notes belong in the body of the
//! issue. The comparison ignores nothing but the style of line ends and white space around the
//! text ([`compare_text`]). A job whose text differs is refused with the reason
//! `text_not_the_issue` and the same block code as every other refusal of this gate, whether or
//! not the issue is on the design track: the issue that the labels are read from must be the issue
//! that the words came from. The result of the comparison is written on the audit line.
//!
//! # What a refusal is
//!
//! The intake outcome is **decline**: the stage returns the decision `decline` with a fixed
//! explanation, and the gate `intake-design-approved` reports `BLOCKED` with the code
//! `design_not_approved`. The stage run is blocked (`S11`, a policy violation) and the job shows
//! as blocked. No job state and no transition is new. The block is listed in
//! `gate_integrity.non_overridable_blocks`, so an override cannot pass it: the one way through is
//! the label on the issue, which everybody can see. No classifier runs for a refused issue.
//!
//! # What the person gets
//!
//! A comment on the issue that says, in plain English, that the design is not approved yet and
//! what to do. It is posted through [`RefusalReplies`](super::seams::RefusalReplies), once for each
//! stage run. It names no person, no id and no list. It does say whether the label is missing, is
//! one of several, or was applied by somebody the factory does not accept approvals from, because
//! that is a fact about the issue that everyone who can see it already knows, and the person needs
//! it to fix the issue.
//!
//! # Fail closed
//!
//! If the rule cannot be read (the policy file is missing, unsafe or broken), the stage does not
//! guess and does not use a default: it blocks the stage run with the environment cause
//! `policy_unloadable`, the way it does when the allowlist cannot be read. It says so in a comment,
//! the composition root logs why, and the health line of the rule fails.

use factory_domain::ids::TenantId;
use factory_domain::policy::authority::{Allowlist, AuthorityPolicy};
use factory_domain::policy::issue_workflow::{DesignGate, DesignLabels, printable_label};
use factory_domain::values::{GitSha, Timestamp};
use serde_json::{Value, json};

use super::authorize::{Authorization, DenialReason, Labeller, authorize_designation};
use super::common::{Executor, GateDefinition, GateFacts};
use crate::handlers::StageError;

/// The gate that reports whether the design of the issue allows work to start.
pub const GATE: &str = "intake-design-approved";

/// The name of the document the stage stores with its decision.
pub const ARTIFACT: &str = "design-gate";

/// The block code in the form the audit log and the logs use.
pub const BLOCK_CODE: &str = "DESIGN_NOT_APPROVED";

/// The same code in the form of the gate report schema (`blocked_reason.code`).
pub const REPORT_BLOCK_CODE: &str = "design_not_approved";

const GATE_TEXT: &str = "intake-design-approved 1.1.0: an issue with a design label starts work only when the label of the approved design is the one design label on the issue, read from the code host now, and a person who holds the approver designation on the allowlist applied it; and the text the job carries is the text of that issue as the code host shows it now.";

/// Why an issue was refused. The set is closed. It is for the audit record and for choosing the
/// reply; it carries no text from the issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// The issue is on the design track and does not carry the approved label.
    NotApproved,
    /// The issue carries no design label now, but one was applied to it and taken off. It is
    /// still on the track and its design is not approved.
    DesignDropped,
    /// The approved label is on the issue together with another design label.
    MoreThanOneDesignLabel,
    /// The approved label was in the list of labels but is not on the issue when its applier is
    /// asked for: it was removed in between.
    ApprovalLabelGone,
    /// The person who applied the approved label does not hold the designation, for the reason
    /// the allowlist gives. The reason is for the audit record only.
    NotAnApprover(DenialReason),
    /// The text the job carries is not the text of the live issue (DG-3). This is decided
    /// whether or not the issue is on the design track.
    TextNotTheIssue,
}

impl RefusalReason {
    /// The word recorded in the document, the report and the audit record.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotApproved => "not_approved",
            Self::DesignDropped => "design_dropped",
            Self::MoreThanOneDesignLabel => "more_than_one_design_label",
            Self::ApprovalLabelGone => "approval_label_gone",
            Self::NotAnApprover(_) => "not_applied_by_an_approver",
            Self::TextNotTheIssue => "text_not_the_issue",
        }
    }

    /// The reply this reason gets.
    #[must_use]
    pub const fn reply(self) -> Reply {
        match self {
            Self::NotApproved | Self::ApprovalLabelGone => Reply::NotApproved,
            Self::DesignDropped => Reply::DesignDropped,
            Self::MoreThanOneDesignLabel => Reply::MoreThanOneDesignLabel,
            Self::NotAnApprover(_) => Reply::NotByAnApprover,
            Self::TextNotTheIssue => Reply::TextNotTheIssue,
        }
    }
}

/// What the comparison of the text of the job with the live issue found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextCheck {
    /// The text the job carries is the text of the issue now.
    Same,
    /// It is not.
    Different,
    /// The caller has no text to compare. The re-check before the pull request is opened
    /// (DG-8) asks about the design only: the text of the job was fixed at intake.
    NotCompared,
}

impl TextCheck {
    /// The word written on the audit line, the stored document and the report.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Same => "same",
            Self::Different => "different",
            Self::NotCompared => "not_compared",
        }
    }
}

/// Compares the text a job carries with the text the live issue gives.
///
/// Both are brought to one form first, and nothing else is ignored: line ends are all `\n` (a text
/// typed on Windows, or a body that the web form saved with `\r\n`) and white space around the
/// whole text is dropped (a file ends with a newline). A different word, letter case, space inside
/// a line or an added sentence is a different text. `live` is the title and body as one text with
/// every secret replaced, and `stored` is the text of the job.
#[must_use]
pub fn compare_text(live: &str, stored: &str) -> TextCheck {
    if canonical_text(live) == canonical_text(stored) {
        TextCheck::Same
    } else {
        TextCheck::Different
    }
}

fn canonical_text(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .trim()
        .to_owned()
}

/// What the design gate decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesignDecision {
    /// No design label: this rule does not apply.
    NotOnTrack,
    /// The design is approved, by this person.
    Approved {
        /// The numeric id of the person who applied the approved label.
        approver: u64,
        /// The version of the allowlist that said so.
        allowlist_version: String,
    },
    /// Refused.
    Refused {
        /// Why.
        reason: RefusalReason,
        /// The design labels seen on the issue, cleaned for display.
        labels_seen: Vec<String>,
        /// The numeric id of the person who applied the approved label, when that was asked.
        applied_by: Option<u64>,
        /// The version of the allowlist that was read.
        allowlist_version: String,
    },
}

impl DesignDecision {
    /// True when the issue may go on.
    #[must_use]
    pub const fn allows_work(&self) -> bool {
        !matches!(self, Self::Refused { .. })
    }
}

/// What the judgement needs besides the labels. Everything is read now, by the caller.
pub struct Judging<'a> {
    /// The rule.
    pub gate: &'a DesignGate,
    /// The authority rules.
    pub authority: &'a AuthorityPolicy,
    /// The allowlist as it is now.
    pub allowlist: &'a Allowlist,
    /// The tenant.
    pub tenant: TenantId,
    /// The repository, as `owner/name`.
    pub repository: &'a str,
    /// The time.
    pub now: &'a Timestamp,
}

/// Judges the labels of an issue. Pure.
///
/// `applied_by` is who applied the approved label (numeric id, login and kind of account), as the
/// code host reports it now, or `None` when the label is not on the issue. It is consulted only
/// when the approved label is the one design label.
///
/// `text` is what the comparison of the text of the job with the live issue found. A text that is
/// different refuses a job that the labels would let through (DG-3); a refusal for the labels
/// keeps its own reason, and the audit line still says that the text was different.
#[must_use]
pub fn judge(
    judging: &Judging<'_>,
    labels: DesignLabels,
    applied_by: Option<Labeller<'_>>,
    text: TextCheck,
) -> DesignDecision {
    let allowlist_version = judging.allowlist.version_hash().to_owned();
    let refused = |reason, labels_seen, applied_by| DesignDecision::Refused {
        reason,
        labels_seen,
        applied_by,
        allowlist_version: allowlist_version.clone(),
    };
    let by_the_labels = match labels {
        DesignLabels::NotOnTrack => DesignDecision::NotOnTrack,
        DesignLabels::NotApproved { seen } => refused(RefusalReason::NotApproved, seen, None),
        DesignLabels::Dropped { seen } => refused(RefusalReason::DesignDropped, seen, None),
        DesignLabels::Ambiguous { seen } => {
            refused(RefusalReason::MoreThanOneDesignLabel, seen, None)
        }
        DesignLabels::ApprovalLabelOnly => {
            let seen = vec![printable_label(judging.gate.approved_label())];
            match authorize_designation(
                judging.gate.approved_by(),
                judging.authority,
                judging.allowlist,
                judging.tenant,
                judging.repository,
                applied_by,
                judging.now,
            ) {
                Authorization::Authorized {
                    actor,
                    allowlist_version,
                } => DesignDecision::Approved {
                    approver: actor,
                    allowlist_version,
                },
                Authorization::Denied {
                    reason: DenialReason::NoLabel,
                    ..
                } => refused(RefusalReason::ApprovalLabelGone, seen, None),
                Authorization::Denied { actor, reason, .. } => {
                    refused(RefusalReason::NotAnApprover(reason), seen, actor)
                }
            }
        }
    };
    match (by_the_labels, text) {
        (DesignDecision::NotOnTrack | DesignDecision::Approved { .. }, TextCheck::Different) => {
            refused(RefusalReason::TextNotTheIssue, Vec::new(), None)
        }
        (decided, _) => decided,
    }
}

/// The comment a person gets, by case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// The design is not approved yet.
    NotApproved,
    /// The approved label is on the issue together with another design label.
    MoreThanOneDesignLabel,
    /// The approved label was applied by somebody the factory does not accept approvals from.
    NotByAnApprover,
    /// A design label was applied and taken off, and the design is not approved.
    DesignDropped,
    /// The factory could not check, because its own policy cannot be used.
    CannotCheck,
    /// The text of the job is not the text of the issue (DG-3).
    TextNotTheIssue,
    /// Work had started, and the factory stopped before it opened the pull request, because the
    /// design is not approved as the issue shows it now (DG-8).
    DesignWithdrawn,
    /// Work had started, and the factory stopped before it opened the pull request, because it
    /// could not check the design again: its own policy cannot be used (DG-8).
    CannotCheckAgain,
}

impl Reply {
    /// The plain-English text. `trigger` is the label that asks the factory to work and
    /// `approved` the label of the approved design, both from protected configuration. The text
    /// holds nothing from the issue, names nobody and says nothing about any list.
    #[must_use]
    pub fn text(self, trigger: &str, approved: &str) -> String {
        match self {
            Self::NotApproved => format!(
                "The factory did not start work on this issue because its design is not approved yet. \
                 An issue with a label that starts with `design:` is on the design track. \
                 The factory starts work on it only after the label `{approved}` is on the issue. \
                 To go on, finish the design and merge its pull request. \
                 Then ask an approver of this repository to apply `{approved}`. \
                 After that, apply the `{trigger}` label again."
            ),
            Self::MoreThanOneDesignLabel => format!(
                "The factory did not start work on this issue because the state of its design is not clear. \
                 The issue carries `{approved}` together with another design label. \
                 Remove the label that is out of date, so that only one design label is left. \
                 Then apply the `{trigger}` label again. \
                 The factory starts work only when `{approved}` is the one design label on the issue."
            ),
            Self::NotByAnApprover => format!(
                "The factory did not start work on this issue. \
                 The label `{approved}` is on it, but the person who applied it is not someone the factory accepts design approvals from. \
                 Ask an approver of this repository to apply `{approved}` themselves. \
                 Remove the label first, and let the approver add it again. \
                 After that, apply the `{trigger}` label again."
            ),
            Self::DesignDropped => format!(
                "The factory did not start work on this issue because it is on the design track and its design is not approved. \
                 The issue once had a label that starts with `design:`, and that label was taken off. \
                 Taking the label off does not leave the track. \
                 To go on, ask an approver of this repository to apply `{approved}`. \
                 After that, apply the `{trigger}` label again."
            ),
            Self::CannotCheck => format!(
                "The factory did not start work on this issue because it could not check whether the design is approved. \
                 The problem is on the factory's side, and nothing in the issue needs to change. \
                 Ask the person who runs the factory for this repository to look at it. \
                 Then apply the `{trigger}` label again."
            ),
            Self::TextNotTheIssue => format!(
                "The factory did not start work on this job because the text of this job is not the text of the issue as it is now. \
                 The factory works only from the title and the body of the issue. \
                 If you want to add a note or change a word, put it in the body of the issue, \
                 or send the job again with the text of the issue as it is. \
                 If somebody edited the issue after the job was made, apply the `{trigger}` label again so that the factory reads the new words."
            ),
            Self::DesignWithdrawn => format!(
                "The factory stopped before it opened the pull request, because the design of this issue is not approved as the issue shows it now. \
                 No pull request was opened. \
                 The approval may have been taken off, the design may have been reopened, another design label may have been added, or the approval may have been applied again by someone the factory does not accept approvals from. \
                 To go on, make sure `{approved}` is the one design label on the issue and that an approver of this repository applied it. \
                 Then ask the person who runs the factory to unblock the job, or apply the `{trigger}` label again to start a new one."
            ),
            Self::CannotCheckAgain => format!(
                "The factory stopped before it opened the pull request, because it could not check again whether the design is still approved. \
                 The problem is on the factory's side, and nothing in the issue needs to change. \
                 No pull request was opened. \
                 Ask the person who runs the factory for this repository to look at it. \
                 Then ask them to unblock the job, or apply the `{trigger}` label again to start a new one."
            ),
        }
    }
}

/// How the reply went, for the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyStatus {
    /// The comment is on the issue.
    Posted,
    /// The host refused, or the issue is gone. It will not be tried again.
    NotSent,
}

impl ReplyStatus {
    const fn word(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::NotSent => "not_sent",
        }
    }
}

/// The document the stage stores with its decision, which `evaluate` reads back to write the
/// report. It holds the labels as cleaned for display and numbers, and no text of the issue.
#[must_use]
pub fn document(
    decision: &DesignDecision,
    approving_label: &str,
    reply: Option<ReplyStatus>,
    text: TextCheck,
) -> Value {
    let mut out = json!({
        "schema_version": 1,
        "approving_label": approving_label,
        "text": text.word(),
    });
    if let Some(map) = out.as_object_mut() {
        match decision {
            DesignDecision::NotOnTrack => {
                map.insert("result".into(), json!("not_on_track"));
            }
            DesignDecision::Approved {
                approver,
                allowlist_version,
            } => {
                map.insert("result".into(), json!("approved"));
                map.insert("approved_by".into(), json!(approver));
                map.insert("allowlist_version".into(), json!(allowlist_version));
            }
            DesignDecision::Refused {
                reason,
                labels_seen,
                applied_by,
                allowlist_version,
            } => {
                map.insert("result".into(), json!("refused"));
                map.insert("block_code".into(), json!(BLOCK_CODE));
                map.insert("reason".into(), json!(reason.code()));
                map.insert("labels_seen".into(), json!(labels_seen));
                map.insert("applied_by".into(), json!(applied_by));
                map.insert("allowlist_version".into(), json!(allowlist_version));
                if let Some(reply) = reply {
                    map.insert("reply".into(), json!(reply.word()));
                }
            }
        }
    }
    out
}

/// True when the stored document says the issue was refused.
#[must_use]
pub fn is_refused(document: &Value) -> bool {
    document["result"] == "refused"
}

/// The reason line of the audit record, in fixed words and numbers and the labels cleaned for
/// display and quoted as a list. It names the issue and the design labels seen, and ends with what
/// the comparison of the text of the job with the live issue found. The caller passes the line
/// through the secret redactor before it is stored.
#[must_use]
pub fn audit_reason(
    decision: &DesignDecision,
    issue: &str,
    reply: Option<ReplyStatus>,
    text: TextCheck,
) -> String {
    let compared = format!(
        "text of the job compared with the live issue: {}",
        text.word()
    );
    match decision {
        DesignDecision::NotOnTrack => {
            format!(
                "design gate: issue {issue} carries no design label, so the rule does not apply; {compared}"
            )
        }
        DesignDecision::Approved {
            approver,
            allowlist_version,
        } => format!(
            "design gate passed: issue {issue}; the approved label was applied by user id {approver}, who holds the approver designation; allowlist version {allowlist_version}; {compared}"
        ),
        DesignDecision::Refused {
            reason,
            labels_seen,
            applied_by,
            allowlist_version,
        } => {
            let why = match reason {
                RefusalReason::NotAnApprover(denial) => {
                    format!("{}: {denial:?}", reason.code())
                }
                other => other.code().to_owned(),
            };
            format!(
                "design gate refused ({BLOCK_CODE}): issue {issue}; reason {why}; design labels seen {}; approved label applied by user id {}; allowlist version {allowlist_version}; reply {}; {compared}",
                quoted(labels_seen),
                applied_by.map_or_else(|| "none".to_owned(), |id| id.to_string()),
                reply.map_or("not attempted", ReplyStatus::word),
            )
        }
    }
}

/// The label names as a JSON array of strings. The names are already printable ASCII with no
/// separator in them ([`printable_label`]); quoting them as well means a name is one item of the
/// list and can never be read as a field of the line, whatever the cleaning missed.
fn quoted(labels: &[String]) -> String {
    serde_json::to_string(labels).unwrap_or_else(|_| "[]".to_owned())
}

/// The reason line of the audit record of the re-check before the pull request is opened (DG-8):
/// the line of [`audit_reason`] with the moment in front.
#[must_use]
pub fn recheck_audit_reason(
    decision: &DesignDecision,
    issue: &str,
    reply: Option<ReplyStatus>,
) -> String {
    format!(
        "design re-check before the pull request is opened: {}",
        audit_reason(decision, issue, reply, TextCheck::NotCompared)
    )
}

/// The reason line when the re-check could not read the issue from the code host. The pull request
/// is not opened: a re-check that cannot be made is never a pass, and the condition is reported
/// as degraded on the record.
#[must_use]
pub fn recheck_unreadable_reason(issue: &str) -> String {
    format!(
        "design re-check before the pull request is opened: degraded, the code host could not be read for issue {issue}, so the design could not be checked again; the pull request was not opened and the attempt failed closed"
    )
}

/// The reason line when the re-check could not judge the issue because its rule cannot be read.
#[must_use]
pub fn recheck_unjudgeable_reason(issue: &str, reply: Option<ReplyStatus>) -> String {
    format!(
        "design re-check before the pull request is opened: degraded, the issue workflow policy or the allowlist cannot be used, so the design of issue {issue} could not be checked again; the pull request was not opened; reply {}",
        reply.map_or("not attempted", ReplyStatus::word)
    )
}

/// The reason line for an issue the stage could not judge because its rule cannot be read.
#[must_use]
pub fn unjudgeable_reason(issue: &str, reply: Option<ReplyStatus>) -> String {
    format!(
        "design gate could not judge issue {issue} ({BLOCK_CODE} is not decided): the issue workflow policy cannot be used, so intake refuses the issue; reply {}",
        reply.map_or("not attempted", ReplyStatus::word)
    )
}

/// The sentence a person reads in the report, by reason. `reason` is one of
/// [`RefusalReason::code`]; an unknown word gets the general sentence.
fn explanation(reason: &str) -> &'static str {
    match reason {
        "design_dropped" => {
            "The issue once carried a design label that was taken off. It is still on the design track and its design is not approved."
        }
        "more_than_one_design_label" => {
            "The state of the design is not clear: the approved label is on the issue together with another design label."
        }
        "not_applied_by_an_approver" => {
            "The approved label is on the issue, but the person who applied it does not hold the approver designation."
        }
        "text_not_the_issue" => {
            "The text the job carries is not the text of the issue as it is now. The factory acts only on the text of the issue."
        }
        _ => "The issue is on the design track and its design is not approved yet.",
    }
}

/// The title of the report, by reason.
fn report_title(reason: &str) -> &'static str {
    match reason {
        "text_not_the_issue" => "The text of the job is not the text of the issue",
        _ => "The design is not approved",
    }
}

/// What the report asks for, by reason (`blocked_reason.requires`).
fn report_requirement(reason: &str) -> &'static str {
    match reason {
        "text_not_the_issue" => {
            "the text of the job to be the title and the body of the issue as it is now"
        }
        _ => {
            "the label of the approved design, applied by a person who holds the approver designation"
        }
    }
}

/// The sentence of the failure of the outcome gate, by the stored document: why the request does
/// not go on.
#[must_use]
pub fn stop_sentence(document: &Value) -> &'static str {
    if document["reason"] == "text_not_the_issue" {
        "The request does not go on until its text is the text of the issue."
    } else {
        "The request does not go on until the design is approved."
    }
}

/// The facts of the report for the gate `intake-design-approved`, from the stored document.
///
/// # Errors
/// [`StageError::InvalidOutput`] when the document is not one the stage wrote.
pub fn gate_facts(document: &Value, commit: &GitSha) -> Result<GateFacts, StageError> {
    let definition = GateDefinition {
        id: GATE,
        version: "1.1.0",
        text: GATE_TEXT,
        commit: commit.clone(),
    };
    let result = document["result"]
        .as_str()
        .ok_or(StageError::InvalidOutput)?;
    let text = document["text"].as_str().unwrap_or("not_compared");
    let evidence_of = |lines: Vec<String>| {
        let mut all = vec![format!("result={result}"), format!("text={text}")];
        all.extend(lines);
        all
    };
    let base =
        |outcome: &'static str, title: &str, reason: &str, evidence: Vec<String>| GateFacts {
            definition: definition.clone(),
            outcome,
            title: title.to_owned(),
            reason: reason.to_owned(),
            failures: Vec::new(),
            blocked: None,
            fidelity: "real",
            executor: Executor::InProcess,
            commands: Vec::new(),
            tools: vec![("factory-intake".to_owned(), "1.0.0".to_owned())],
            evidence,
        };
    match result {
        "not_on_track" => Ok(base(
            "PASSED",
            "The issue is not on the design track",
            "The issue carries no design label, so it is a small, clear change and needs no design approval.",
            evidence_of(Vec::new()),
        )),
        "approved" => {
            let approver = document["approved_by"]
                .as_u64()
                .ok_or(StageError::InvalidOutput)?;
            Ok(base(
                "PASSED",
                "The design is approved",
                "The label of the approved design is the one design label on the issue, and a person who holds the approver designation applied it.",
                evidence_of(vec![
                    format!("approved_by={approver}"),
                    format!(
                        "allowlist_version={}",
                        document["allowlist_version"].as_str().unwrap_or_default()
                    ),
                ]),
            ))
        }
        "refused" => {
            let reason = document["reason"]
                .as_str()
                .ok_or(StageError::InvalidOutput)?;
            let seen: Vec<&str> = document["labels_seen"]
                .as_array()
                .ok_or(StageError::InvalidOutput)?
                .iter()
                .filter_map(Value::as_str)
                .collect();
            let mut facts = base(
                "BLOCKED",
                report_title(reason),
                explanation(reason),
                evidence_of(vec![
                    format!("block_code={BLOCK_CODE}"),
                    format!("reason={reason}"),
                    format!("labels_seen={}", seen.join("|")),
                    format!(
                        "applied_by={}",
                        document["applied_by"]
                            .as_u64()
                            .map_or_else(|| "none".to_owned(), |id| id.to_string())
                    ),
                    format!(
                        "allowlist_version={}",
                        document["allowlist_version"].as_str().unwrap_or_default()
                    ),
                ]),
            );
            facts.blocked = Some((REPORT_BLOCK_CODE, report_requirement(reason).to_owned()));
            Ok(facts)
        }
        _ => Err(StageError::InvalidOutput),
    }
}

/// The title and the description of the normalized request of a refused issue. The stage runs no
/// classifier for it, so these are fixed sentences. The text of the issue is not in them.
pub const REFUSED_TITLE: &str = "The design is not approved yet";

/// See [`REFUSED_TITLE`].
pub const REFUSED_DESCRIPTION: &str = "This issue is on the design track and its design is not approved. The factory has not started work. It starts after an approver applies the label of the approved design.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_comparison_ignores_line_ends_and_outer_white_space_and_nothing_else() {
        let issue = "Add a flag\n\nIt prints JSON.\nIt exits 0.";
        for same in [
            issue,
            "Add a flag\r\n\r\nIt prints JSON.\r\nIt exits 0.",
            "Add a flag\r\rIt prints JSON.\rIt exits 0.",
            "\n  Add a flag\n\nIt prints JSON.\nIt exits 0.\n\n",
            "\t\r\nAdd a flag\n\nIt prints JSON.\nIt exits 0. \t",
        ] {
            assert_eq!(compare_text(issue, same), TextCheck::Same, "{same:?}");
            assert_eq!(compare_text(same, issue), TextCheck::Same, "{same:?}");
        }
        for different in [
            "",
            "Add a flag",
            "add a flag\n\nIt prints JSON.\nIt exits 0.",
            "Add a flag\n\nIt prints JSON.\nIt exits 1.",
            "Add a flag\n\nIt prints  JSON.\nIt exits 0.",
            "Add a flag\n\nIt prints JSON.\n\nIt exits 0.",
            "Add a flag\n\nIt prints JSON.\nIt exits 0.\nAlso delete the logs.",
            "Add a flag It prints JSON. It exits 0.",
        ] {
            assert_eq!(
                compare_text(issue, different),
                TextCheck::Different,
                "{different:?}"
            );
        }
        // Two empty texts are the same text, and the stage never gets here with an empty issue.
        assert_eq!(compare_text("", " \n"), TextCheck::Same);
    }

    #[test]
    fn the_words_of_the_comparison_are_the_ones_the_record_uses() {
        assert_eq!(TextCheck::Same.word(), "same");
        assert_eq!(TextCheck::Different.word(), "different");
        assert_eq!(TextCheck::NotCompared.word(), "not_compared");
        assert_eq!(RefusalReason::TextNotTheIssue.code(), "text_not_the_issue");
        assert_eq!(
            RefusalReason::TextNotTheIssue.reply(),
            Reply::TextNotTheIssue
        );
    }

    #[test]
    fn the_replies_of_the_recheck_say_that_no_pull_request_was_opened_and_what_to_do() {
        for reply in [Reply::DesignWithdrawn, Reply::CannotCheckAgain] {
            let text = reply.text("factory", "design: approved");
            assert!(
                text.starts_with("The factory stopped before it opened the pull request"),
                "{reply:?}"
            );
            assert!(text.contains("No pull request was opened."), "{reply:?}");
            assert!(text.contains("unblock the job"), "{reply:?}");
            assert!(text.contains("`factory`"), "{reply:?}");
            for forbidden in [
                "@",
                "allowlist",
                "numeric",
                "user id",
                "login",
                "http",
                "sha256",
            ] {
                assert!(!text.contains(forbidden), "{reply:?} says {forbidden}");
            }
        }
        assert!(
            Reply::DesignWithdrawn
                .text("factory", "design: approved")
                .contains("`design: approved`")
        );
    }

    #[test]
    fn every_reply_names_the_labels_and_says_what_to_do_and_none_names_a_person() {
        for reply in [
            Reply::NotApproved,
            Reply::MoreThanOneDesignLabel,
            Reply::NotByAnApprover,
            Reply::DesignDropped,
            Reply::CannotCheck,
            Reply::TextNotTheIssue,
        ] {
            let text = reply.text("factory", "design: approved");
            assert!(text.contains("`factory`"), "{reply:?}");
            assert!(
                text.starts_with("The factory did not start work"),
                "{reply:?}"
            );
            for forbidden in [
                "@",
                "allowlist",
                "numeric",
                "user id",
                "login",
                "http",
                "sha256",
            ] {
                assert!(!text.contains(forbidden), "{reply:?} says {forbidden}");
            }
        }
        // Four of them tell the person which label to look at.
        for reply in [
            Reply::NotApproved,
            Reply::MoreThanOneDesignLabel,
            Reply::NotByAnApprover,
            Reply::DesignDropped,
        ] {
            assert!(
                reply
                    .text("factory", "design: approved")
                    .contains("`design: approved`")
            );
        }
    }

    #[test]
    fn the_replies_are_not_the_same_text() {
        let texts: Vec<String> = [
            Reply::NotApproved,
            Reply::MoreThanOneDesignLabel,
            Reply::NotByAnApprover,
            Reply::DesignDropped,
            Reply::CannotCheck,
            Reply::TextNotTheIssue,
            Reply::DesignWithdrawn,
            Reply::CannotCheckAgain,
        ]
        .iter()
        .map(|reply| reply.text("factory", "design: approved"))
        .collect();
        for (i, a) in texts.iter().enumerate() {
            for b in &texts[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn a_stored_document_that_is_not_ours_is_not_read() {
        let commit = GitSha::parse("1405df66cbe219b0bf6355bc3d60361a8376b6b4").expect("a commit");
        for bad in [
            json!({}),
            json!({ "result": "maybe" }),
            json!({ "result": "approved" }),
            json!({ "result": "refused" }),
            json!({ "result": "refused", "reason": "not_approved" }),
        ] {
            assert!(gate_facts(&bad, &commit).is_err(), "{bad}");
        }
    }
}
