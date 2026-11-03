//! The design is checked again right before the pull request is opened (DG-8).
//!
//! The product owner decided on 2026-11-02 that approval is not a one-time check at intake. An
//! approver can take `design: approved` back, reopen the design, or a second design label can
//! appear while the job runs. Before the delivery stage pushes the factory branch and opens the
//! draft pull request, it reads the labels and the events of the issue again and judges them with
//! the code that intake uses ([`DesignJudge`], not a copy of it). The issue must still be off the
//! design track, or on it with `design: approved` as its one design label, applied by a person who
//! holds the approver designation now.
//!
//! # What the stage does with the answer
//!
//! * **Allowed.** The stage goes on. The record says the re-check passed.
//! * **Refused.** No branch is pushed and no pull request is opened. The stage ends with
//!   `Blocked(DesignNotApproved)`: the stage run is blocked, the job shows as blocked, and the
//!   status step writes `factory: blocked` and its comment, which says the work stopped while the
//!   pull request was being prepared. One comment on the issue says why (the design is not approved
//!   as the issue shows it now) and how to go on. The block names no gate, so the engine has no
//!   stored block and refuses every override; the way through is the approver's label, and then an
//!   operator unblocks the job or the requester applies the factory label again.
//! * **The code host cannot be read, or answers something that cannot be trusted.** The stage
//!   fails closed: the attempt ends with an error, so no pull request is opened, and the engine
//!   tries again as it does for any failed read. The condition is **degraded**, not a pass: the
//!   audit record says that the design could not be checked again and that nothing was opened. If
//!   the code host stays unreadable, the retries run out and the job fails, visibly.
//! * **The rule or the allowlist cannot be read.** Same as intake: the stage run is blocked with
//!   the environment cause `policy_unloadable`, and one comment says the factory could not check.
//!
//! The comment is best effort here. The refusal and its record do not wait for it: the audit record
//! is written first, and a comment that cannot be posted now does not turn a block into a retry.

use std::sync::Arc;

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::machines::guards::EnvironmentCause;
use factory_domain::policy::issue_workflow::{ReplyCap, ReplyKind};
use factory_domain::vocabulary::Fidelity;
use factory_ports::githost::{GitScope, IssueRef};

use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::handlers::{StageContext, StageError};
use crate::stages::intake::design::{self, DesignDecision, Reply, ReplyStatus};
use crate::stages::intake::judge::{DesignJudge, DesignStop, Judged, Question};
use crate::stages::intake::seams::{AllowlistSource, RefusalReplies};

/// What the delivery stage needs to check the design again.
#[derive(Clone)]
pub struct DesignRecheck {
    judge: DesignJudge,
    allowlists: Arc<dyn AllowlistSource>,
    replies: Arc<dyn RefusalReplies>,
    trigger_label: String,
}

impl std::fmt::Debug for DesignRecheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DesignRecheck { .. }")
    }
}

impl DesignRecheck {
    /// A re-check over the judge intake uses, the allowlist as it is now, the way to answer a
    /// person on the issue, and the label that asks the factory to work (named in the comment).
    #[must_use]
    pub fn new(
        judge: DesignJudge,
        allowlists: Arc<dyn AllowlistSource>,
        replies: Arc<dyn RefusalReplies>,
        trigger_label: String,
    ) -> Self {
        Self {
            judge,
            allowlists,
            replies,
            trigger_label,
        }
    }

    /// Says whether the parts are real or fakes: the weakest of them.
    #[must_use]
    pub fn fidelity(&self) -> Fidelity {
        if [
            self.judge.fidelity(),
            self.allowlists.fidelity(),
            self.replies.fidelity(),
        ]
        .contains(&Fidelity::Fake)
        {
            Fidelity::Fake
        } else {
            Fidelity::Real
        }
    }

    /// Checks the design of `issue` again, and records what it found.
    ///
    /// # Errors
    /// [`StageError::Blocked`] with `DesignNotApproved` when the design is not approved now,
    /// [`StageError::Environment`] when the rule or the allowlist cannot be read, and the error of
    /// the failed read otherwise. In every one of these the pull request must not be opened.
    pub async fn check(
        &self,
        ctx: &mut StageContext<'_>,
        scope: &GitScope,
        issue: &IssueRef,
    ) -> Result<(), StageError> {
        let issue_text = format!(
            "{}/{}#{}",
            issue.repo.owner(),
            issue.repo.name(),
            issue.number
        );
        let now = ctx.ports.clock.now();
        let Ok(allowlist) = self.allowlists.current(scope.tenant).await else {
            return self.cannot_judge(ctx, scope, issue, &issue_text).await;
        };
        let judged = self
            .judge
            .judge(Question {
                scope,
                issue,
                allowlist: &allowlist,
                now,
                stored_text: None,
            })
            .await;
        match judged {
            Ok(Judged { rule, decision, .. }) => {
                if matches!(decision, DesignDecision::Refused { .. }) {
                    // The record first, then the reply, then the record of the reply (DG-9). Every
                    // refusal gets the same comment: the design is not approved as the issue shows
                    // it now. The record keeps the reason, and it is in the store before the reply
                    // is tried, whatever happens to the attempt after (DR-3).
                    ctx.record_now(
                        AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),
                        self.judge.redacted_reason(design::recheck_audit_reason(
                            &decision,
                            &issue_text,
                            Some(ReplyStatus::ToFollow),
                        )),
                    )
                    .await?;
                    let cap = rule.reply_cap(ReplyKind::Withdrawal);
                    let status = self
                        .reply(
                            ctx,
                            scope,
                            issue,
                            Reply::DesignWithdrawn,
                            rule.approved_label(),
                            &cap,
                        )
                        .await;
                    ctx.note_audit_because(
                        AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),
                        design::reply_reason(design::RECHECK_REPLY_LEAD, &issue_text, status, &cap),
                    );
                    tracing::warn!(
                        "delivery stops before the pull request: the design of the issue is not approved now"
                    );
                    return Err(StageError::Blocked(BlockedCode::DesignNotApproved));
                }
                ctx.note_audit_because(
                    AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Granted),
                    self.judge.redacted_reason(design::recheck_audit_reason(
                        &decision,
                        &issue_text,
                        None,
                    )),
                );
                Ok(())
            }
            Err(DesignStop::Unjudgeable) => self.cannot_judge(ctx, scope, issue, &issue_text).await,
            Err(DesignStop::Stage(error)) => {
                // The code host could not be read, or said something that cannot be trusted. The
                // pull request is not opened. This is a degraded condition on the record, and the
                // attempt fails so that the engine tries again.
                ctx.note_audit_because(
                    AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),
                    design::recheck_unreadable_reason(&issue_text),
                );
                tracing::warn!(
                    "delivery stops before the pull request: the design could not be checked again because the issue could not be read (degraded)"
                );
                Err(error)
            }
        }
    }

    /// The rule or the allowlist cannot be used: block the run, say so, and open nothing.
    async fn cannot_judge(
        &self,
        ctx: &mut StageContext<'_>,
        scope: &GitScope,
        issue: &IssueRef,
        issue_text: &str,
    ) -> Result<(), StageError> {
        ctx.record_now(
            AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),
            design::recheck_unjudgeable_reason(issue_text, Some(ReplyStatus::ToFollow)),
        )
        .await?;
        // The rule cannot be read, so the cap cannot be either: the least one applies.
        let cap = ReplyCap::when_the_policy_cannot_be_read(ReplyKind::Withdrawal);
        let status = self
            .reply(ctx, scope, issue, Reply::CannotCheckAgain, "", &cap)
            .await;
        ctx.note_audit_because(
            AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),
            design::reply_reason(design::RECHECK_REPLY_LEAD, issue_text, status, &cap),
        );
        // The audit record names the issue; a log field would be text of outside origin, so the
        // line says only what happened.
        tracing::error!(
            "delivery stops before the pull request: the issue workflow policy or the allowlist cannot be used, so the design cannot be checked again"
        );
        Err(StageError::Environment(EnvironmentCause::PolicyUnloadable))
    }

    /// One comment for each stage run. A comment that cannot be posted is noted and changes
    /// nothing.
    async fn reply(
        &self,
        ctx: &StageContext<'_>,
        scope: &GitScope,
        issue: &IssueRef,
        reply: Reply,
        approved_label: &str,
        cap: &ReplyCap,
    ) -> ReplyStatus {
        let key = format!("design-recheck-{}", ctx.identity.stage_run);
        let text = reply.text(&self.trigger_label, approved_label);
        ReplyStatus::of(
            self.replies
                .post(scope.tenant, issue, &key, &text, cap)
                .await,
        )
    }
}
