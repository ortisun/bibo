//! The approval request: what the approval stage stores for the person to see, and what a
//! decision is judged against.
//!
//! The stage writes it when the delivery has been checked. It names the pull request, the binding
//! the person is shown (head, tree, base, manifest and specification version), whether every gate
//! is clear, how many translation warnings need a decision, and the facts of the change that the
//! policy needs to decide who may approve. An approval that is not bound to exactly this binding,
//! or that arrives after the request expired, is refused.

use factory_domain::values::{GitSha, Sha256Digest, Timestamp};
use factory_domain::vocabulary::RiskTier;
use serde_json::{Value, json};

use super::command::Seen;
use crate::stages::validation::Binding;

/// The hours an approval counts for, from `approval_binding.expires_after_hours`.
pub const VALID_HOURS: u64 = 72;

/// The rule id of the reviewer warning that needs a recorded decision (ADR 0009 item 17).
pub const TRANSLATION_WARNING: &str = "translation-unfaithful";

/// What the person is asked to decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// The repository, `owner/name`.
    pub repository: String,
    /// The pull request number.
    pub pull_request: u64,
    /// The factory branch.
    pub head_branch: String,
    /// The protected branch.
    pub base_branch: String,
    /// The head of the pull request: the documentation commit when the documenting stage made
    /// one, and the code head otherwise. An approval is bound to this commit.
    pub pr_head: GitSha,
    /// The git tree of that head.
    pub tree: GitSha,
    /// The base commit.
    pub base: GitSha,
    /// The hash of the evidence manifest.
    pub manifest: Sha256Digest,
    /// The version of the frozen specification.
    pub spec_version: u32,
    /// Every gate is `PASSED` or does not apply, and none is blocked or failed.
    pub gates_clear: bool,
    /// Open warnings of the rule `translation-unfaithful` in the gate reports.
    pub open_translation_warnings: u32,
    /// The tier the policy computed.
    pub tier: RiskTier,
    /// A protected path changes.
    pub protected_path_change: bool,
    /// A sensitive file changes.
    pub sensitive_file_change: bool,
    /// A new direct dependency is added.
    pub new_dependency: bool,
    /// The numeric GitHub id of the person who asked for the job.
    pub requester: u64,
    /// The values the gate reports are bound to. They are compared with the world again when an
    /// approval is recorded (ADR 0010). Its head is the code head the gates ran on, which is under
    /// `pr_head` when documentation was committed.
    pub evidence_binding: Binding,
    /// When the request was made.
    pub created_at: Timestamp,
}

impl ApprovalRequest {
    /// The document the stage stores.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "kind": "approval-request",
            "repository": self.repository,
            "pull_request": self.pull_request,
            "head_branch": self.head_branch,
            "base_branch": self.base_branch,
            "pr_head": self.pr_head.as_str(),
            "tree": self.tree.as_str(),
            "base": self.base.as_str(),
            "manifest": self.manifest.as_str(),
            "spec_version": self.spec_version,
            "gates_clear": self.gates_clear,
            "open_translation_warnings": self.open_translation_warnings,
            "tier": self.tier.as_str(),
            "protected_path_change": self.protected_path_change,
            "sensitive_file_change": self.sensitive_file_change,
            "new_dependency": self.new_dependency,
            "requester": self.requester,
            "binding": self.evidence_binding.to_json(),
            "created_at": self.created_at.as_text(),
            "valid_hours": VALID_HOURS,
        })
    }

    /// Reads a stored request. `None` for anything that is not one.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let text = |key: &str| value.get(key).and_then(Value::as_str);
        let number = |key: &str| value.get(key).and_then(Value::as_u64);
        let flag = |key: &str| value.get(key).and_then(Value::as_bool);
        if text("kind")? != "approval-request" {
            return None;
        }
        Some(Self {
            repository: text("repository")?.to_owned(),
            pull_request: number("pull_request")?,
            head_branch: text("head_branch")?.to_owned(),
            base_branch: text("base_branch")?.to_owned(),
            pr_head: GitSha::parse(text("pr_head")?).ok()?,
            tree: GitSha::parse(text("tree")?).ok()?,
            base: GitSha::parse(text("base")?).ok()?,
            manifest: Sha256Digest::parse(text("manifest")?).ok()?,
            spec_version: u32::try_from(number("spec_version")?).ok()?,
            gates_clear: flag("gates_clear")?,
            open_translation_warnings: u32::try_from(number("open_translation_warnings")?).ok()?,
            tier: RiskTier::parse(text("tier")?).ok()?,
            protected_path_change: flag("protected_path_change")?,
            sensitive_file_change: flag("sensitive_file_change")?,
            new_dependency: flag("new_dependency")?,
            requester: number("requester")?,
            evidence_binding: Binding::from_json(value.get("binding")?)?,
            created_at: Timestamp::parse(text("created_at")?).ok()?,
        })
    }

    /// When the request stops being valid.
    #[must_use]
    pub fn expires_at(&self) -> Option<Timestamp> {
        self.created_at
            .checked_add(std::time::Duration::from_secs(VALID_HOURS * 3600))
    }

    /// The binding a person is shown, with the ledger head they saw added by the caller.
    #[must_use]
    pub fn seen_with(&self, ledger_head: Sha256Digest) -> Seen {
        Seen {
            pr_head: self.pr_head.clone(),
            tree: self.tree.clone(),
            base: self.base.clone(),
            manifest: self.manifest.clone(),
            spec_version: self.spec_version,
            ledger_head,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn request() -> ApprovalRequest {
        ApprovalRequest {
            repository: "example-org/word-count".to_owned(),
            pull_request: 7,
            head_branch: "factory/job-1".to_owned(),
            base_branch: "main".to_owned(),
            pr_head: GitSha::parse(&"a".repeat(40)).expect("a sha"),
            tree: GitSha::parse(&"b".repeat(40)).expect("a sha"),
            base: GitSha::parse(&"c".repeat(40)).expect("a sha"),
            manifest: Sha256Digest::of(b"manifest"),
            spec_version: 1,
            gates_clear: true,
            open_translation_warnings: 0,
            tier: RiskTier::Low,
            protected_path_change: false,
            sensitive_file_change: false,
            new_dependency: false,
            requester: 1001,
            evidence_binding: Binding {
                implementation_result: Sha256Digest::of(b"result"),
                base_commit: GitSha::parse(&"c".repeat(40)).expect("a sha"),
                head_commit: GitSha::parse(&"a".repeat(40)).expect("a sha"),
                policy_hash: Sha256Digest::of(b"policy"),
                image_digest: Sha256Digest::of(b"image"),
                definition_hash: Sha256Digest::of(b"definitions"),
            },
            created_at: Timestamp::parse("2026-10-27T10:00:00Z").expect("a time"),
        }
    }

    #[test]
    fn a_request_survives_its_document_form() {
        let original = request();
        assert_eq!(
            ApprovalRequest::from_json(&original.to_json()),
            Some(original)
        );
    }

    #[test]
    fn a_document_that_is_not_a_request_is_not_read() {
        assert_eq!(ApprovalRequest::from_json(&json!({})), None);
        let mut value = request().to_json();
        value["kind"] = json!("something-else");
        assert_eq!(ApprovalRequest::from_json(&value), None);
        let mut value = request().to_json();
        value["pr_head"] = json!("not a sha");
        assert_eq!(ApprovalRequest::from_json(&value), None);
    }

    #[test]
    fn a_request_expires_after_seventy_two_hours() {
        let expires = request().expires_at().expect("a time");
        assert_eq!(expires.as_text(), "2026-10-30T10:00:00Z");
    }
}
