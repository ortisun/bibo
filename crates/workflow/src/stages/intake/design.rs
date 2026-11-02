//! The design gate: an issue on the design track starts work only when its design is approved, and
//! approved by a person whom the allowlist knows as an approver.
//!
//! # The rule
//!
//! Intake reads the labels of the issue from the code host now (the webhook payload is not used)
//! and classifies them with [`DesignGate::classify`]:
//!
//! * **No design label.** A small, clear change. Nothing here touches it.
//! * **Any design label and no `design: approved`.** Refused, with the block code
//!   `DESIGN_NOT_APPROVED`.
//! * **`design: approved` together with another design label.** Refused: a reopened design whose
//!   old label has not been cleaned up is not an approved design.
//! * **`design: approved` alone.** The person who applied it must hold the designation that the
//!   policy names (`intake_requirements.design_approved_by`, `approver` by default), found by
//!   numeric id on the protected allowlist, not narrowed away from this repository, not expired,
//!   a human. A label applied by anybody else is refused. GitHub gives triage rights to many
//!   people, and the Action only checks that a design document exists, so the label alone proves
//!   nothing about who decided.
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

use super::authorize::{Authorization, DenialReason, authorize_designation};
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

const GATE_TEXT: &str = "intake-design-approved 1.0.0: an issue with a design label starts work only when the label of the approved design is the one design label on the issue, read from the code host now, and a person who holds the approver designation on the allowlist applied it.";

/// Why an issue was refused. The set is closed. It is for the audit record and for choosing the
/// reply; it carries no text from the issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// The issue is on the design track and does not carry the approved label.
    NotApproved,
    /// The approved label is on the issue together with another design label.
    MoreThanOneDesignLabel,
    /// The approved label was in the list of labels but is not on the issue when its applier is
    /// asked for: it was removed in between.
    ApprovalLabelGone,
    /// The person who applied the approved label does not hold the designation, for the reason
    /// the allowlist gives. The reason is for the audit record only.
    NotAnApprover(DenialReason),
}

impl RefusalReason {
    /// The word recorded in the document, the report and the audit record.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotApproved => "not_approved",
            Self::MoreThanOneDesignLabel => "more_than_one_design_label",
            Self::ApprovalLabelGone => "approval_label_gone",
            Self::NotAnApprover(_) => "not_applied_by_an_approver",
        }
    }

    /// The reply this reason gets.
    #[must_use]
    pub const fn reply(self) -> Reply {
        match self {
            Self::NotApproved | Self::ApprovalLabelGone => Reply::NotApproved,
            Self::MoreThanOneDesignLabel => Reply::MoreThanOneDesignLabel,
            Self::NotAnApprover(_) => Reply::NotByAnApprover,
        }
    }
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
/// `applied_by` is the numeric id and the login of the person who applied the approved label, as
/// the code host reports them now, or `None` when the label is not on the issue. It is consulted
/// only when the approved label is the one design label.
#[must_use]
pub fn judge(
    judging: &Judging<'_>,
    labels: DesignLabels,
    applied_by: Option<(u64, &str)>,
) -> DesignDecision {
    let allowlist_version = judging.allowlist.version_hash().to_owned();
    let refused = |reason, labels_seen, applied_by| DesignDecision::Refused {
        reason,
        labels_seen,
        applied_by,
        allowlist_version: allowlist_version.clone(),
    };
    match labels {
        DesignLabels::NotOnTrack => DesignDecision::NotOnTrack,
        DesignLabels::NotApproved { seen } => refused(RefusalReason::NotApproved, seen, None),
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
    /// The factory could not check, because its own policy cannot be used.
    CannotCheck,
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
            Self::CannotCheck => format!(
                "The factory did not start work on this issue because it could not check whether the design is approved. \
                 The problem is on the factory's side, and nothing in the issue needs to change. \
                 Ask the person who runs the factory for this repository to look at it. \
                 Then apply the `{trigger}` label again."
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
) -> Value {
    let mut out = json!({ "schema_version": 1, "approving_label": approving_label });
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
/// display. It names the issue and the design labels seen.
#[must_use]
pub fn audit_reason(decision: &DesignDecision, issue: &str, reply: Option<ReplyStatus>) -> String {
    match decision {
        DesignDecision::NotOnTrack => {
            format!(
                "design gate: issue {issue} carries no design label, so the rule does not apply"
            )
        }
        DesignDecision::Approved {
            approver,
            allowlist_version,
        } => format!(
            "design gate passed: issue {issue}; the approved label was applied by user id {approver}, who holds the approver designation; allowlist version {allowlist_version}"
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
                "design gate refused ({BLOCK_CODE}): issue {issue}; reason {why}; design labels seen [{}]; approved label applied by user id {}; allowlist version {allowlist_version}; reply {}",
                labels_seen.join(", "),
                applied_by.map_or_else(|| "none".to_owned(), |id| id.to_string()),
                reply.map_or("not attempted", ReplyStatus::word),
            )
        }
    }
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
        "more_than_one_design_label" => {
            "The state of the design is not clear: the approved label is on the issue together with another design label."
        }
        "not_applied_by_an_approver" => {
            "The approved label is on the issue, but the person who applied it does not hold the approver designation."
        }
        _ => "The issue is on the design track and its design is not approved yet.",
    }
}

/// The facts of the report for the gate `intake-design-approved`, from the stored document.
///
/// # Errors
/// [`StageError::InvalidOutput`] when the document is not one the stage wrote.
pub fn gate_facts(document: &Value, commit: &GitSha) -> Result<GateFacts, StageError> {
    let definition = GateDefinition {
        id: GATE,
        version: "1.0.0",
        text: GATE_TEXT,
        commit: commit.clone(),
    };
    let result = document["result"]
        .as_str()
        .ok_or(StageError::InvalidOutput)?;
    let evidence_of = |lines: Vec<String>| {
        let mut all = vec![format!("result={result}")];
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
                "The design is not approved",
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
            facts.blocked = Some((
                REPORT_BLOCK_CODE,
                "the label of the approved design, applied by a person who holds the approver designation"
                    .to_owned(),
            ));
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
    fn every_reply_names_the_labels_and_says_what_to_do_and_none_names_a_person() {
        for reply in [
            Reply::NotApproved,
            Reply::MoreThanOneDesignLabel,
            Reply::NotByAnApprover,
            Reply::CannotCheck,
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
        // Three of them tell the person which label to look at.
        for reply in [
            Reply::NotApproved,
            Reply::MoreThanOneDesignLabel,
            Reply::NotByAnApprover,
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
            Reply::CannotCheck,
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
