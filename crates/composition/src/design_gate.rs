//! What the design gate of the intake stage is given by the composition root (ADR 0016).
//!
//! The gate itself is in `factory_workflow::stages::intake::design`. It needs two things from
//! outside, and this module is where they come from:
//!
//! * [`FileDesignGatePolicy`] reads the design rule from `policies/issue-workflow.yaml` in the
//!   protected checkout **at every attempt**, with the strict loader. A file that is missing, is
//!   inside a job workspace, does not parse, has a field it does not know, lacks
//!   `design_approved_by` or breaks a rule of the policy gives no rule at all, and the stage then
//!   refuses the issue. There is no default and no "last good" copy: the gate is a control, not an
//!   observation. The status writer of ADR 0017 makes the opposite choice for the same file,
//!   because a label that shows state decides nothing; a rule that decides who may start work
//!   cannot be switched off by breaking its file.
//! * [`IssueRefusalReplies`] posts the comment that answers a person on the issue, through the
//!   `ChangeHost` port with a token narrowed to the one repository, the way the worker answers a
//!   label from someone who may not ask ([`crate::intake_rejections`]). It does not use the signed
//!   request of that path: the stage runs inside the worker, so no untrusted channel stands between
//!   the decision and the reply.
//!
//! # Health
//!
//! The worker has no readiness endpoint of its own. [`FileDesignGatePolicy::health_check`] is the
//! line that says whether the rule can be read: `fail` with the reason when it cannot, which keeps a
//! process that reports it from being ready (a control that cannot work is not "degraded"), and
//! `pass` otherwise. The worker prints it when it starts, and the stage logs the same fact each
//! time it refuses an issue for that reason.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use factory_contracts::policy::{PolicyLoader, ProtectedPolicySource};
use factory_domain::ids::{JobId, TenantId};
use factory_domain::policy::issue_workflow::DesignGate;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::clock::IdGenerator;
use factory_ports::githost::{ChangeHost, CommentTarget, GitHostError, GitScope, IssueRef};
use factory_workflow::stages::intake::seams::{
    DesignGatePolicy, RefusalReplies, ReplyError, SeamError,
};

use crate::health::CheckResult;

/// The name of the check in the health line.
pub const CHECK_NAME: &str = "design gate";

/// The design rule, read from the protected checkout at every call.
#[derive(Debug, Clone)]
pub struct FileDesignGatePolicy {
    root: PathBuf,
}

impl FileDesignGatePolicy {
    /// A source over the protected checkout at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Reads and checks the rule now.
    ///
    /// # Errors
    /// A plain sentence that says why the rule cannot be used. It names the file and the key or
    /// the rule, and it never holds the text of the file.
    pub fn load(&self) -> Result<DesignGate, String> {
        let source = ProtectedPolicySource::protected_default_branch(&self.root, &[])
            .map_err(|error| format!("policies/issue-workflow.yaml cannot be read: {error}"))?;
        let loaded = PolicyLoader::load_issue_workflow(&source)
            .map_err(|error| format!("policies/issue-workflow.yaml cannot be used: {error}"))?;
        loaded.document.design_gate().map_err(|problems| {
            problems.first().map_or_else(
                || "policies/issue-workflow.yaml is unsound".to_owned(),
                |problem| {
                    format!(
                        "policies/issue-workflow.yaml is unsound at {}: {}",
                        problem.path, problem.message
                    )
                },
            )
        })
    }

    /// The line for a health report: `pass` when the rule can be read, `fail` with the reason when
    /// it cannot. Never `degraded`: while it fails, intake refuses every issue.
    #[must_use]
    pub fn health_check(&self) -> CheckResult {
        match self.load() {
            Ok(gate) => CheckResult::pass(
                CHECK_NAME,
                &format!(
                    "the rule can be read; an issue on the design track needs `{}` applied by the {} designation",
                    gate.approved_label(),
                    gate.approved_by()
                ),
            ),
            Err(reason) => CheckResult::fail(
                CHECK_NAME,
                &format!("{reason}. Intake refuses every issue until the file is repaired."),
            ),
        }
    }
}

#[async_trait]
impl DesignGatePolicy for FileDesignGatePolicy {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn current(&self) -> Result<DesignGate, SeamError> {
        self.load().map_err(|reason| {
            tracing::error!(
                reason = %reason,
                "the design rule cannot be read: intake refuses the issue"
            );
            SeamError::Unavailable
        })
    }
}

/// Posts the comment that answers a person on the issue the stage refused.
#[derive(Clone)]
pub struct IssueRefusalReplies {
    host: Arc<dyn ChangeHost>,
    ids: Arc<dyn IdGenerator>,
}

impl IssueRefusalReplies {
    /// Replies through `host`. `ids` names the credential of each call: a reply has no job of its
    /// own, so its token gets an identifier that no other call shares, and ending it never touches
    /// a job's tokens or the token of a retry.
    #[must_use]
    pub fn new(host: Arc<dyn ChangeHost>, ids: Arc<dyn IdGenerator>) -> Self {
        Self { host, ids }
    }
}

/// What became of a reply: delivered, to be tried again, or not to be delivered. A host that cannot
/// be reached or that asks the caller to slow down is tried again; every other refusal (a revoked
/// or narrow token, a gone issue, text the host will not take) is final.
fn settle<T>(posted: Result<T, GitHostError>) -> Result<(), ReplyError> {
    match posted {
        Ok(_) => Ok(()),
        Err(GitHostError::Unavailable | GitHostError::RateLimited { .. }) => Err(ReplyError::Later),
        Err(_) => Err(ReplyError::NotSent),
    }
}

#[async_trait]
impl RefusalReplies for IssueRefusalReplies {
    fn fidelity(&self) -> Fidelity {
        // The host says what it is, and the caller (the handler) takes the weakest of its parts.
        Fidelity::Real
    }

    async fn post(
        &self,
        tenant: TenantId,
        issue: &IssueRef,
        key: &str,
        text: &str,
    ) -> Result<(), ReplyError> {
        // The approval stage holds the narrowest token that may write `issues`: it reads, and
        // writes `issues` only. The identifier of the scope is not a job, so ending its tokens
        // does not touch any job's. The comment is found again by its key, not by this
        // identifier, so a retry that gets another one still leaves one comment.
        let scope = GitScope {
            tenant,
            job: JobId::from_uuid(self.ids.new_uuid()),
            stage: StageKind::Approval,
            repo: issue.repo.clone(),
        };
        let target = CommentTarget::Issue(issue.clone());
        let posted = self
            .host
            .post_comment(&scope, &target, text, &format!("intake-{key}"))
            .await;
        let result = settle(posted);
        if result != Err(ReplyError::Later) {
            let _ = self.host.revoke_job_tokens(scope.job).await;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_that_is_down_or_busy_is_tried_again_and_every_other_refusal_is_final() {
        assert_eq!(settle(Ok(())), Ok(()));
        assert_eq!(
            settle::<()>(Err(GitHostError::Unavailable)),
            Err(ReplyError::Later)
        );
        assert_eq!(
            settle::<()>(Err(GitHostError::RateLimited { retry_after: None })),
            Err(ReplyError::Later)
        );
        for final_refusal in [
            GitHostError::NotFound,
            GitHostError::Unauthorized,
            GitHostError::Forbidden,
            GitHostError::UnsafeText,
        ] {
            assert_eq!(
                settle::<()>(Err(final_refusal.clone())),
                Err(ReplyError::NotSent),
                "{final_refusal:?}"
            );
        }
    }
}
