//! Reading the issue and judging its design, for every stage that has to ask (ADR 0016).
//!
//! Intake asks before work starts. The delivery stage asks again right before it opens the pull
//! request (DG-8), so that an approval taken back while the job ran stops the pull request. Both
//! call [`DesignJudge::judge`]: one code path reads the rule, fetches the issue from the code host
//! now, keeps an issue on the design track after its design label was taken off, finds who applied
//! the approving label, and hands the labels to [`design::judge`]. A second copy of that logic
//! would drift from the first, and the second asker is the one nobody tests every day.
//!
//! The judge reads and decides. It posts nothing and records nothing: each stage answers the person
//! and writes its audit record in its own words.

use std::sync::Arc;

use factory_domain::policy::PolicyEngine;
use factory_domain::policy::authority::Allowlist;
use factory_domain::policy::issue_workflow::{DesignGate, DesignLabels};
use factory_domain::redaction::Redactor;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::Fidelity;
use factory_ports::githost::{GitScope, IssueRef, IssueSource};

use super::authorize::Labeller;
use super::design::{self, DesignDecision, Judging, TextCheck};
use super::seams::DesignGatePolicy;
use crate::handlers::StageError;

/// Why the design could not be judged.
#[derive(Debug)]
pub enum DesignStop {
    /// The rule cannot be read. The caller refuses the issue and blocks the run.
    Unjudgeable,
    /// A read failed or the answer cannot be trusted. The attempt fails and may be tried again.
    Stage(StageError),
}

/// What the judge found.
#[derive(Debug)]
pub struct Judged {
    /// The rule that was in force.
    pub rule: DesignGate,
    /// What it decided.
    pub decision: DesignDecision,
    /// What the comparison of the text of the job with the live issue found, or
    /// [`TextCheck::NotCompared`] when the caller gave no text.
    pub text: TextCheck,
}

/// What the judge is asked.
pub struct Question<'a> {
    /// The scope of the credential that reads the issue: the tenant, the job, the stage and the
    /// one repository.
    pub scope: &'a GitScope,
    /// The issue the job is for.
    pub issue: &'a IssueRef,
    /// The allowlist as it is now.
    pub allowlist: &'a Allowlist,
    /// The time.
    pub now: Timestamp,
    /// The text the job carries, to be compared with the live issue (DG-3), or `None` to judge
    /// the design alone.
    pub stored_text: Option<&'a str>,
}

/// Reads an issue and judges its design.
#[derive(Clone)]
pub struct DesignJudge {
    issues: Arc<dyn IssueSource>,
    design: Arc<dyn DesignGatePolicy>,
    policy: Arc<PolicyEngine>,
    redactor: Arc<Redactor>,
}

impl std::fmt::Debug for DesignJudge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DesignJudge { .. }")
    }
}

impl DesignJudge {
    /// A judge over the code host, the rule, the authority rules and the redactor of the job.
    #[must_use]
    pub fn new(
        issues: Arc<dyn IssueSource>,
        design: Arc<dyn DesignGatePolicy>,
        policy: Arc<PolicyEngine>,
        redactor: Arc<Redactor>,
    ) -> Self {
        Self {
            issues,
            design,
            policy,
            redactor,
        }
    }

    /// Says whether the code host and the rule are real or fakes: the weakest of the two.
    #[must_use]
    pub fn fidelity(&self) -> Fidelity {
        if [self.issues.fidelity(), self.design.fidelity()].contains(&Fidelity::Fake) {
            Fidelity::Fake
        } else {
            Fidelity::Real
        }
    }

    /// The reason line of an audit record with every secret replaced. A label name is text of
    /// outside origin and could be shaped like a secret. A line the redactor cannot judge is not
    /// stored: a sentence that says so takes its place.
    #[must_use]
    pub fn redacted_reason(&self, reason: String) -> String {
        self.redacted(
            &reason,
            "design gate: the reason was withheld because it could not be checked for secrets",
        )
    }

    /// The text with every secret replaced. A text the redactor cannot judge is not stored:
    /// `withheld` takes its place.
    #[must_use]
    pub fn redacted(&self, text: &str, withheld: &str) -> String {
        match self.redactor.redact_str(text) {
            Ok(redacted) => redacted.output.into_owned(),
            Err(_) => withheld.to_owned(),
        }
    }

    /// Judges the design of the issue. The labels come from a live fetch of the issue and the
    /// applier of the approved label from the timeline of the issue: nothing a webhook carried is
    /// used. A read that fails, or an issue other than the one asked for, is an error (never a
    /// pass).
    ///
    /// When `stored_text` is given, the title and the body that the live fetch returned are joined
    /// the way a webhook job stores them, have each secret replaced the way the store does, and are
    /// compared with it ([`design::compare_text`]).
    ///
    /// # Errors
    /// [`DesignStop::Unjudgeable`] when the rule cannot be read, [`DesignStop::Stage`] when a read
    /// fails.
    pub async fn judge(&self, question: Question<'_>) -> Result<Judged, DesignStop> {
        let Question {
            scope,
            issue,
            allowlist,
            now,
            stored_text,
        } = question;
        let rule = self
            .design
            .current()
            .await
            .map_err(|_| DesignStop::Unjudgeable)?;
        let fetched = self
            .issues
            .fetch_issue(scope, issue)
            .await
            .map_err(|_| DesignStop::Stage(StageError::Tool))?;
        if fetched.reference != *issue {
            return Err(DesignStop::Stage(StageError::Tool));
        }
        let text = match stored_text {
            None => TextCheck::NotCompared,
            Some(stored) => {
                let (live, _) =
                    redact_request(&self.redactor, &request_text(&fetched.title, &fetched.body))
                        .map_err(DesignStop::Stage)?;
                design::compare_text(&live, stored)
            }
        };
        let mut labels = rule.classify(&fetched.labels);
        if labels == DesignLabels::NotOnTrack {
            // No design label now. The track is sticky: a design label that was applied and taken
            // off keeps the issue on it. That is in the events of the issue, which must be read to
            // the end: a list that is cut is an error here, and never "nothing was applied".
            let applied_before = self
                .issues
                .labels_ever_applied(scope, issue)
                .await
                .map_err(|_| DesignStop::Stage(StageError::Tool))?;
            labels = rule.classify_past(&applied_before);
        }
        let applied = if labels == DesignLabels::ApprovalLabelOnly {
            self.issues
                .label_application(scope, issue, rule.approved_label())
                .await
                .map_err(|_| DesignStop::Stage(StageError::Tool))?
        } else {
            None
        };
        let repository = format!("{}/{}", issue.repo.owner(), issue.repo.name());
        let decision = design::judge(
            &Judging {
                gate: &rule,
                authority: &self.policy.authority,
                allowlist,
                tenant: scope.tenant,
                repository: &repository,
                now: &now,
            },
            labels,
            applied.as_ref().map(Labeller::of),
            text,
        );
        Ok(Judged {
            rule,
            decision,
            text,
        })
    }
}

/// Title and body as one text, the way the API stores a request: the title, a blank line, the body.
/// A missing part leaves no separator.
pub(super) fn request_text(title: &str, body: &str) -> String {
    match (title.is_empty(), body.is_empty()) {
        (false, false) => format!("{title}\n\n{body}"),
        (false, true) => title.to_owned(),
        (true, _) => body.to_owned(),
    }
}

/// The text with every secret replaced, and how many were. A text the redactor cannot judge is an
/// internal error: it is neither stored nor compared.
pub(super) fn redact_request(redactor: &Redactor, text: &str) -> Result<(String, u64), StageError> {
    let redacted = redactor
        .redact_str(text)
        .map_err(|_| StageError::Internal)?;
    Ok((
        redacted.output.clone().into_owned(),
        redacted.report.replacements(),
    ))
}
