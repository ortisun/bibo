//! A person's decision about a translation warning, and how the approval counts them.
//!
//! The documentation reviewer's rule `translation-unfaithful` raises a warning when a translated
//! text may not say what the original says. The approval stage counts the open warnings in the
//! approval request (`open_translation_warnings`), and the guard `G_APPROVER_AUTHORIZED` holds an
//! approval back until every one of them has a recorded decision of the person who approves
//! (ADR 0009 item 17, the policy row `acknowledge_documentation_warning`).
//!
//! A decision is bound to one warning of one approval request: the stage run, the manifest hash of
//! the request the person saw, and the number of the warning (counted from 1, in the order the
//! reports list them). A new request, made after the evidence changed, has another manifest and
//! needs its decisions again. The person who decides is the one an approval must come from: a
//! decision of someone else does not count for this person's approval, and neither does the
//! decision of a person who is no longer on the allowlist (the composition root drops it).

use factory_domain::ids::{JobId, StageRunId, TenantId};
use factory_domain::policy::decision::{AuthorizedApproval, Designation, GithubUserId};
use factory_domain::values::{Sha256Digest, Timestamp};
use serde_json::{Value, json};

use crate::gates::supply_chain::approval::{
    ApprovalError, DecisionScope, MAX_REASON_CHARS, MIN_REASON_CHARS, WARNING_ACTION,
};

/// How the statement of the ledger claim of a recorded decision begins.
pub const STATEMENT_PREFIX: &str = "A person acknowledged translation warning ";

/// The description of the artifact evidence that holds the decision.
pub const ARTIFACT_NOTE: &str = "translation-warning-decision";

/// What an approval request says about its warnings, read from the document the stage stored:
/// how many are open, and the manifest hash of the request. `None` for any other document.
#[must_use]
pub fn warnings_of_request(document: &Value) -> Option<(u32, Sha256Digest)> {
    if document.get("kind")?.as_str()? != "approval-request" {
        return None;
    }
    let open = u32::try_from(document.get("open_translation_warnings")?.as_u64()?).ok()?;
    let manifest = Sha256Digest::parse(document.get("manifest")?.as_str()?).ok()?;
    Some((open, manifest))
}

/// The record of one authorized decision about one warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarningDecision {
    /// The approval stage run the request belongs to.
    pub stage_run: StageRunId,
    /// The manifest hash of the approval request the person saw.
    pub manifest: Sha256Digest,
    /// The number of the warning, from 1.
    pub warning: u32,
    /// The numeric id of the person.
    pub approver: GithubUserId,
    /// The designation the allowlist gave them.
    pub designation: Designation,
    /// The version of the allowlist the decision was read from.
    pub allowlist_version: String,
    /// The hash of the policy bundle in force when it was decided.
    pub policy_hash: Sha256Digest,
    /// The tenant and the job it was decided for.
    pub scope: DecisionScope,
    /// Why, in the person's words.
    pub reason: String,
    /// When.
    pub decided_at: Timestamp,
}

impl WarningDecision {
    /// Records a decision.
    ///
    /// # Errors
    /// [`ApprovalError::WrongAction`] when the proof is for another action, and
    /// [`ApprovalError::NoReason`] when the reason is shorter than the policy asks.
    pub fn record(
        authorization: &AuthorizedApproval,
        (stage_run, manifest, warning): (StageRunId, Sha256Digest, u32),
        policy_hash: Sha256Digest,
        scope: DecisionScope,
        reason: &str,
    ) -> Result<Self, ApprovalError> {
        if authorization.action() != WARNING_ACTION {
            return Err(ApprovalError::WrongAction);
        }
        let reason = reason.trim();
        if reason.chars().count() < MIN_REASON_CHARS {
            return Err(ApprovalError::NoReason);
        }
        Ok(Self {
            stage_run,
            manifest,
            warning,
            approver: authorization.approver(),
            designation: authorization.designation(),
            allowlist_version: authorization.allowlist_version().to_owned(),
            policy_hash,
            scope,
            reason: reason.chars().take(MAX_REASON_CHARS).collect(),
            decided_at: *authorization.decided_at(),
        })
    }

    /// The statement of the ledger claim for the decision.
    #[must_use]
    pub fn statement(&self) -> String {
        format!(
            "{STATEMENT_PREFIX}{} of the approval request {}.",
            self.warning, self.manifest
        )
    }

    /// The document stored as the artifact of the ledger entry.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "action": WARNING_ACTION,
            "kind": "translation-warning",
            "stage_run_id": self.stage_run.as_text(),
            "manifest": self.manifest.as_str(),
            "warning": self.warning,
            "approver_id": self.approver.get(),
            "designation": self.designation.as_str(),
            "allowlist_version": self.allowlist_version,
            "policy_hash": self.policy_hash.as_str(),
            "tenant_id": self.scope.tenant.as_text(),
            "job_id": self.scope.job.as_text(),
            "reason": self.reason,
            "decided_at": self.decided_at.as_text(),
        })
    }

    /// Reads a document written by [`to_json`](Self::to_json). `None` for anything else.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let text = |name: &str| value.get(name).and_then(Value::as_str);
        if text("action")? != WARNING_ACTION || text("kind")? != "translation-warning" {
            return None;
        }
        let reason = text("reason")?;
        if reason.chars().count() < MIN_REASON_CHARS {
            return None;
        }
        Some(Self {
            stage_run: StageRunId::parse(text("stage_run_id")?).ok()?,
            manifest: Sha256Digest::parse(text("manifest")?).ok()?,
            warning: u32::try_from(value.get("warning")?.as_u64()?).ok()?,
            approver: GithubUserId::new(value.get("approver_id")?.as_u64()?)?,
            designation: Designation::parse(text("designation")?)?,
            allowlist_version: text("allowlist_version")?.to_owned(),
            policy_hash: Sha256Digest::parse(text("policy_hash")?).ok()?,
            scope: DecisionScope {
                tenant: TenantId::parse(text("tenant_id")?).ok()?,
                job: JobId::parse(text("job_id")?).ok()?,
            },
            reason: reason.to_owned(),
            decided_at: Timestamp::parse(text("decided_at")?).ok()?,
        })
    }
}

/// True when `person` has decided on every one of the `open` warnings of the approval request
/// whose manifest is `manifest`, for this stage run, this tenant and this job. A request with no
/// open warning needs no decision. Decisions of another person, another request, another stage
/// run or another job count for nothing, and so does one by a person who is not an approver.
#[must_use]
pub fn all_decided(
    decisions: &[WarningDecision],
    person: u64,
    (scope, stage_run, manifest): (&DecisionScope, StageRunId, &Sha256Digest),
    open: u32,
) -> bool {
    (1..=open).all(|warning| {
        decisions.iter().any(|held| {
            held.warning == warning
                && held.approver.get() == person
                && held.scope == *scope
                && held.stage_run == stage_run
                && held.manifest == *manifest
                && matches!(
                    held.designation,
                    Designation::Approver | Designation::SecurityApprover
                )
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> DecisionScope {
        DecisionScope {
            tenant: TenantId::from_uuid(uuid::Uuid::from_u128(1)),
            job: JobId::from_uuid(uuid::Uuid::from_u128(2)),
        }
    }

    fn run() -> StageRunId {
        StageRunId::from_uuid(uuid::Uuid::from_u128(3))
    }

    fn manifest() -> Sha256Digest {
        Sha256Digest::of(b"manifest")
    }

    fn decision(warning: u32, person: u64) -> WarningDecision {
        WarningDecision {
            stage_run: run(),
            manifest: manifest(),
            warning,
            approver: GithubUserId::new(person).expect("an id"),
            designation: Designation::Approver,
            allowlist_version: "sha256:aa".to_owned(),
            policy_hash: Sha256Digest::of(b"policy"),
            scope: scope(),
            reason: "The translation says what the original says.".to_owned(),
            decided_at: Timestamp::parse("2026-10-29T12:00:00Z").expect("a time"),
        }
    }

    #[test]
    fn a_request_with_no_open_warning_needs_no_decision_and_one_with_two_needs_two() {
        let m = manifest();
        let s = scope();
        assert!(all_decided(&[], 7, (&s, run(), &m), 0));
        assert!(!all_decided(&[], 7, (&s, run(), &m), 2));
        let one = [decision(1, 7)];
        assert!(!all_decided(&one, 7, (&s, run(), &m), 2));
        let both = [decision(1, 7), decision(2, 7)];
        assert!(all_decided(&both, 7, (&s, run(), &m), 2));
    }

    #[test]
    fn a_decision_counts_for_its_person_its_request_its_run_and_its_job_only() {
        let m = manifest();
        let s = scope();
        let both = [decision(1, 7), decision(2, 7)];
        // Another person's approval.
        assert!(!all_decided(&both, 8, (&s, run(), &m), 2));
        // Another request: the evidence changed, so the manifest did.
        let other = Sha256Digest::of(b"another manifest");
        assert!(!all_decided(&both, 7, (&s, run(), &other), 2));
        // Another stage run.
        let elsewhere = StageRunId::from_uuid(uuid::Uuid::from_u128(4));
        assert!(!all_decided(&both, 7, (&s, elsewhere, &m), 2));
        // Another job and another tenant.
        let other_job = DecisionScope {
            job: JobId::from_uuid(uuid::Uuid::from_u128(5)),
            ..scope()
        };
        assert!(!all_decided(&both, 7, (&other_job, run(), &m), 2));
        // A decision of a person who is not an approver counts for nothing.
        let mut operator = both.clone();
        operator[0].designation = Designation::Operator;
        assert!(!all_decided(&operator, 7, (&s, run(), &m), 2));
        // A warning past the number open is not a decision on one that is.
        let numbered_wrong = [decision(2, 7), decision(3, 7)];
        assert!(!all_decided(&numbered_wrong, 7, (&s, run(), &m), 2));
    }

    #[test]
    fn a_record_reads_back_as_it_was_written() {
        let written = decision(2, 7);
        assert_eq!(
            WarningDecision::from_json(&written.to_json()),
            Some(written.clone())
        );
        let mut package = written.to_json();
        package["kind"] = json!("package");
        assert_eq!(WarningDecision::from_json(&package), None);
        let mut short = written.to_json();
        short["reason"] = json!("ok");
        assert_eq!(WarningDecision::from_json(&short), None);
    }

    #[test]
    fn the_warnings_of_a_request_are_read_from_the_stored_document() {
        let document = json!({
            "kind": "approval-request",
            "open_translation_warnings": 3,
            "manifest": manifest().as_str(),
        });
        assert_eq!(warnings_of_request(&document), Some((3, manifest())));
        assert_eq!(
            warnings_of_request(&json!({"kind": "validation-evidence"})),
            None
        );
        assert_eq!(
            warnings_of_request(
                &json!({"kind": "approval-request", "open_translation_warnings": -1})
            ),
            None
        );
    }
}
