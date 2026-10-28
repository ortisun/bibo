//! The service that applies a person's decision.
//!
//! It gathers the facts [`judge`](super::judge::judge) reads, judges, and then applies the answer
//! in this order, so that a failure in the middle leaves a state that can be repeated:
//!
//! 1. the decision is **recorded** with `ApprovalOps::record_approval` (the approval id is derived
//!    from the command id, so a replayed command finds its own row), together with an audit
//!    record that names the sender's numeric id, the designation, the allowlist version, the
//!    policy hash and the channel;
//! 2. the engine is asked to **move the stage run** (`Engine::decide` or `Engine::control`). If the
//!    engine refuses, the approval row stays: it is recorded and ineffective, which is what the
//!    catalog expects for a failing gate (NT-MRG-01).
//!
//! The service has no way to merge. After an approval the stage run passes and the job goes on to
//! its approved state; the person merges on the code host.
//!
//! A refusal is audited. An unauthorized sender and a text that is not a command get **no reply**
//! (no oracle for outsiders); the caller reads [`ServiceError::reply_allowed`].

use std::sync::Arc;
use std::time::Duration;

use factory_domain::ids::CorrelationId;
use factory_domain::ids::{ApprovalId, AuditEventId, StageRunId, TenantId};
use factory_domain::policy::PolicyEngine;
use factory_domain::policy::decision::Designation;
use factory_domain::redaction::Redactor;
use factory_domain::scope::TenantScope;
use factory_domain::values::{GitSha, HumanText, Sha256Digest, Slug};
use factory_domain::vocabulary::{RiskTier, StageKind};
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::{
    ChangeHost, CommentTarget, GitHostError, GitScope, IssueSource, PullRequestRef,
};
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use factory_ports::store::{
    Approval, ApprovalBinding, ApprovalDecision, ApprovalInvalidation,
    AuditAction as PortAuditAction, AuditActor, AuditDecision as PortAuditDecision, ConstraintRule,
    NewApproval, NewAuditEvent, Store, StoreError,
};

use super::command::{ApprovalCommand, Verb};
use super::judge::{Accepted, Context, Live, Refusal, judge};
use super::request::{ApprovalRequest, VALID_HOURS};
use super::seams::ApprovalSources;
use crate::commands::{Actor, Decision, JobCommand, Subject};
use crate::engine::{Engine, EngineError};
use crate::stages::delivery::binding::{self, Now};
use crate::stages::delivery::text::fragment;
use crate::stages::delivery::{DeliverySources, SeamError};
use factory_domain::machines::invalidation::ArtifactChange;
use factory_ports::store::ApprovalChannel;

/// What the service is built from.
#[derive(Clone)]
pub struct ApprovalDeps {
    /// Moves the stage run.
    pub engine: Arc<Engine>,
    /// Records approvals and audit events.
    pub store: Arc<dyn Store>,
    /// Reads the pull request and the branches, posts the acknowledgement.
    pub host: Arc<dyn ChangeHost>,
    /// Fetches the comment of a command again.
    pub issues: Arc<dyn IssueSource>,
    /// The policy.
    pub policy: Arc<PolicyEngine>,
    /// The hash of the policy bundle in force.
    pub policy_hash: Sha256Digest,
    /// Ledger, tree and bound values.
    pub delivery: Arc<dyn DeliverySources>,
    /// Allowlist, level and the stored request.
    pub approvals: Arc<dyn ApprovalSources>,
    /// The time.
    pub clock: Arc<dyn Clock>,
    /// New identifiers.
    pub ids: Arc<dyn IdGenerator>,
    /// Finds secrets in a person's reason before it is stored.
    pub redactor: Arc<Redactor>,
}

/// What came of a decision that was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The decision is recorded and the stage run moved (or the job command was applied).
    Applied {
        /// The approval row.
        approval: ApprovalId,
    },
    /// The decision is recorded and counts, and the tier needs more approvers before the stage
    /// run can pass.
    Recorded {
        /// The approval row.
        approval: ApprovalId,
        /// How many more distinct approvers the tier needs.
        still_needed: u32,
    },
    /// The command was applied before. Nothing changed.
    Replayed,
}

/// Why a decision did not take effect.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    /// The decision was judged and refused.
    #[error("the decision was refused")]
    Refused(Refusal),
    /// A source of facts could not answer. Nothing was recorded; the caller may try again.
    #[error("a source of facts could not answer")]
    Unavailable,
    /// The engine refused the move after the decision was recorded.
    #[error("the engine refused the move")]
    Engine(String),
}

impl ServiceError {
    /// False when the sender must be told nothing.
    #[must_use]
    pub fn reply_allowed(&self) -> bool {
        match self {
            Self::Refused(refusal) => refusal.may_reply(),
            _ => true,
        }
    }
}

impl From<StoreError> for ServiceError {
    fn from(_: StoreError) -> Self {
        Self::Unavailable
    }
}

impl From<SeamError> for ServiceError {
    fn from(_: SeamError) -> Self {
        Self::Unavailable
    }
}

/// Applies the decisions of people.
#[derive(Clone)]
pub struct ApprovalService {
    deps: ApprovalDeps,
}

impl std::fmt::Debug for ApprovalService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalService { .. }")
    }
}

fn commit_sha(sha: &GitSha) -> Result<CommitSha, ServiceError> {
    CommitSha::parse(sha.as_str()).map_err(|_| ServiceError::Unavailable)
}

fn git_sha(sha: &CommitSha) -> Result<GitSha, ServiceError> {
    GitSha::parse(sha.as_str()).map_err(|_| ServiceError::Unavailable)
}

/// The reason an approval stops counting, for the names of the bound values that changed.
fn invalidation_of(name: &str) -> ApprovalInvalidation {
    match name {
        "base_commit" => ApprovalInvalidation::BaseMoved,
        "image_digest" => ApprovalInvalidation::ImageChange,
        _ => ApprovalInvalidation::PolicyChange,
    }
}

impl ApprovalService {
    /// A service over these dependencies.
    #[must_use]
    pub fn new(deps: ApprovalDeps) -> Self {
        Self { deps }
    }

    fn scope(
        request: &ApprovalRequest,
        tenant: TenantId,
        job: factory_domain::ids::JobId,
    ) -> Result<GitScope, ServiceError> {
        Ok(GitScope {
            tenant,
            job,
            stage: StageKind::Approval,
            repo: RepoRef::parse(&request.repository).map_err(|_| ServiceError::Unavailable)?,
        })
    }

    /// Applies a command.
    ///
    /// # Errors
    /// [`ServiceError`]. A refusal has been audited when this returns.
    pub async fn submit(&self, cmd: ApprovalCommand) -> Result<Outcome, ServiceError> {
        let d = &self.deps;
        let request = d.approvals.request(cmd.tenant, cmd.stage_run).await?;
        let allowlist = d.approvals.allowlist(cmd.tenant).await?;
        let level = d.approvals.level(cmd.tenant, cmd.job).await?;
        let git = Self::scope(&request, cmd.tenant, cmd.job)?;
        let now = d.clock.now();

        // A person's reason is stored, so it is checked for a secret first.
        if d.redactor
            .contains_secret(cmd.reason.as_bytes())
            .unwrap_or(true)
        {
            return Err(ServiceError::Refused(Refusal::MissingReason));
        }

        // Facts that only an approval reads. Reading them for any verb costs four calls.
        let repo = git.repo.clone();
        let pr = d
            .host
            .pull_request_state(
                &git,
                &PullRequestRef {
                    repo: repo.clone(),
                    number: request.pull_request,
                },
            )
            .await
            .map_err(host_unavailable)?;
        let base_branch =
            BranchName::new(&request.base_branch).map_err(|_| ServiceError::Unavailable)?;
        let head_branch =
            BranchName::new(&request.head_branch).map_err(|_| ServiceError::Unavailable)?;
        let base_tip = d
            .host
            .resolve_branch(&git, &base_branch)
            .await
            .map_err(host_unavailable)?;
        let branch_tip = d
            .host
            .resolve_branch(&git, &head_branch)
            .await
            .map_err(host_unavailable)?;
        // Either source saying the head moved is enough: the pull request's own head and the
        // branch it was opened from must both be the head that was shown.
        let shown = commit_sha(&request.pr_head)?;
        let head_now = if pr.head_sha != shown {
            pr.head_sha.clone()
        } else {
            branch_tip
        };
        let run = crate::handlers::RunIdentity {
            tenant: cmd.tenant,
            job: cmd.job,
            correlation: CorrelationId::from_uuid(d.ids.new_uuid()),
            stage_run: cmd.stage_run,
            kind: StageKind::Approval,
        };
        let tree = d.delivery.tree_of(&run, &head_now).await?;
        let ledger = d.delivery.ledger(&run).await?;
        let current = d
            .delivery
            .current_values(&run, &commit_sha(&request.base)?)
            .await?;
        // The evidence is bound to the code head the gates ran on. The head the person was shown
        // may be the documentation commit on top of it, and a move of that head is judged below
        // against what they saw.
        let code_head = commit_sha(&request.evidence_binding.head_commit)?;
        let drift = binding::differences(
            &request.evidence_binding,
            &Now {
                live_base: &base_tip,
                current: &current,
                policy_hash: &d.policy_hash,
                head: &code_head,
                implementation_sha256: &request.evidence_binding.implementation_result,
            },
        )
        .ok_or(ServiceError::Unavailable)?;
        let comment = match (&cmd.comment, cmd.channel) {
            (Some(evidence), ApprovalChannel::GithubComment) => {
                d.issues.fetch_comment(&git, &evidence.comment).await.ok()
            }
            _ => None,
        };

        let head_git = git_sha(&head_now)?;
        let base_git = git_sha(&base_tip)?;
        let outcome = judge(
            &cmd,
            &Context {
                request: &request,
                live: Live {
                    now,
                    pr_open: pr.lifecycle == factory_ports::githost::PullRequestLifecycle::Open,
                    pr_draft: pr.draft,
                    pr_head: &head_git,
                    tree: &tree,
                    base_tip: &base_git,
                    ledger_head: &ledger.head_hash,
                    drift: &drift,
                },
                policy: &d.policy,
                allowlist: &allowlist,
                level,
                tenant: &cmd.tenant,
                comment: comment.as_ref(),
            },
        );
        let accepted = match outcome {
            Ok(accepted) => accepted,
            Err(refusal) => {
                self.refuse(&cmd, &refusal, allowlist.version_hash(), &drift, &request)
                    .await?;
                return Err(ServiceError::Refused(refusal));
            }
        };

        let principal = {
            let mut tx = d.store.begin(TenantScope::new(cmd.tenant)).await?;
            let found = tx.find_principal_by_github_user(cmd.sender.id).await?;
            tx.commit().await?;
            found
        };
        let Some(principal) = principal else {
            let refusal = Refusal::Unauthorized(
                factory_domain::policy::authority::ActionDenialReason::Authority(
                    factory_domain::policy::authority::AuthorityDenial::NotOnAllowlist,
                ),
            );
            self.refuse(&cmd, &refusal, allowlist.version_hash(), &drift, &request)
                .await?;
            return Err(ServiceError::Refused(refusal));
        };
        let approval_id = ApprovalId::from_uuid(cmd.id.as_uuid());
        let actor = Actor {
            tenant: cmd.tenant,
            principal: principal.id,
            command: cmd.id,
        };
        let subject = Subject {
            job: cmd.job,
            stage_run: cmd.stage_run,
        };
        let allowlist_version = allowlist.version_hash().to_owned();

        // An approval is recorded **before** the engine is asked, so that one the engine then
        // refuses stays on record as ineffective. Every other decision is recorded after the
        // engine accepted it: a refused request for rework, for example, must not stop the same
        // person from asking again with a valid target.
        if cmd.verb == Verb::Approve {
            match self
                .record(&cmd, principal.id, &accepted, &request, false)
                .await
            {
                Ok(_) => {}
                Err(ServiceError::Refused(refusal)) => {
                    self.refuse(&cmd, &refusal, &allowlist_version, &drift, &request)
                        .await?;
                    return Err(ServiceError::Refused(refusal));
                }
                Err(other) => return Err(other),
            }
            let still_needed = self.approvals_missing(&cmd, &request).await?;
            if still_needed > 0 {
                return Ok(Outcome::Recorded {
                    approval: approval_id,
                    still_needed,
                });
            }
        }
        let moved = match cmd.verb {
            Verb::Approve => {
                let seen = cmd
                    .seen
                    .as_ref()
                    .ok_or(ServiceError::Refused(Refusal::NotBound))?;
                d.engine
                    .decide(
                        &actor,
                        subject,
                        Decision::Approve {
                            evidence_seen: seen.ledger_head.clone(),
                            warnings_decided: cmd.warnings_decided,
                        },
                    )
                    .await
            }
            Verb::Reject => {
                let reason = HumanText::parse(cmd.reason.trim())
                    .map_err(|_| ServiceError::Refused(Refusal::MissingReason))?;
                d.engine
                    .decide(&actor, subject, Decision::Reject { reason })
                    .await
            }
            Verb::Rework => {
                let target = cmd
                    .rework_target
                    .ok_or(ServiceError::Refused(Refusal::MissingTarget))?;
                d.engine
                    .decide(&actor, subject, Decision::RequestRework { target })
                    .await
            }
            Verb::Pause => d.engine.control(&actor, cmd.job, JobCommand::Pause).await,
            Verb::Resume => d.engine.control(&actor, cmd.job, JobCommand::Resume).await,
            Verb::Cancel => d.engine.control(&actor, cmd.job, JobCommand::Cancel).await,
        };
        let replayed = match moved {
            Ok(()) => false,
            Err(EngineError::Duplicate) => true,
            Err(other) => return Err(ServiceError::Engine(format!("{other}"))),
        };
        let created = if cmd.verb == Verb::Approve {
            !replayed
        } else {
            self.record(&cmd, principal.id, &accepted, &request, true)
                .await?
                && !replayed
        };
        if !created {
            return Ok(Outcome::Replayed);
        }

        // The acknowledgement comment is at most once for a command, whatever the retries.
        if cmd.channel == ApprovalChannel::GithubComment {
            let text = format!(
                "The decision {} by {} is recorded. The factory does not merge or deploy; a person merges this pull request on the code host.",
                cmd.verb.as_str(),
                fragment(cmd.sender.login.as_str()),
            );
            let target = CommentTarget::PullRequest(PullRequestRef {
                repo,
                number: request.pull_request,
            });
            // A comment that cannot be posted does not undo a decision.
            let _ = d
                .host
                .post_comment(&git, &target, &text, &format!("approval-{}", cmd.id))
                .await;
        }
        Ok(Outcome::Applied {
            approval: approval_id,
        })
    }

    /// Writes the approval row (all verbs but `resume`) and the audit record. Returns whether the
    /// row is new. A row that repeats an earlier decision of the same person for the same head
    /// is `AlreadyDecided`, unless the caller tolerates it.
    async fn record(
        &self,
        cmd: &ApprovalCommand,
        approver: factory_domain::ids::PrincipalId,
        accepted: &Accepted,
        request: &ApprovalRequest,
        tolerate_repeat: bool,
    ) -> Result<bool, ServiceError> {
        let d = &self.deps;
        let auth = &accepted.authorization;
        let decision = match cmd.verb {
            Verb::Approve => Some(ApprovalDecision::Approve),
            Verb::Reject => Some(ApprovalDecision::Reject),
            Verb::Rework => Some(ApprovalDecision::Rework),
            Verb::Pause => Some(ApprovalDecision::Pause),
            Verb::Cancel => Some(ApprovalDecision::Cancel),
            // There is no stored decision for a resume: it is a job command, audited below.
            Verb::Resume => None,
        };
        let version = auth.allowlist_version();
        let allowlist_hash =
            Sha256Digest::parse(version).unwrap_or_else(|_| Sha256Digest::of(version.as_bytes()));
        // A decision other than an approval is still bound to the head it was about, so that
        // two rounds of rework by the same person, on different commits, are two rows.
        let binding = accepted.binding.clone().unwrap_or_else(|| ApprovalBinding {
            pr_head: request.pr_head.clone(),
            tree: request.tree.clone(),
            base: request.base.clone(),
            evidence_manifest: request.manifest.clone(),
            spec_version: request.spec_version,
        });
        let mut tx = d.store.begin(TenantScope::new(cmd.tenant)).await?;
        let mut created = true;
        if let Some(decision) = decision {
            let inserted = tx
                .record_approval(NewApproval {
                    id: ApprovalId::from_uuid(cmd.id.as_uuid()),
                    job: cmd.job,
                    stage_run: cmd.stage_run,
                    decision,
                    approver,
                    designation: Slug::parse(auth.designation().as_str())
                        .map_err(|_| ServiceError::Unavailable)?,
                    allowlist_version: allowlist_hash,
                    binding: Some(binding),
                    policy_hash: d.policy_hash.clone(),
                    reason: cmd.reason.clone(),
                    channel: cmd.channel,
                    valid_for: Duration::from_secs(VALID_HOURS * 3600),
                })
                .await;
            match inserted {
                Ok(row) => created = row.created,
                Err(StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent)) => {
                    drop(tx);
                    return if tolerate_repeat {
                        Ok(false)
                    } else {
                        Err(ServiceError::Refused(Refusal::AlreadyDecided))
                    };
                }
                Err(other) => return Err(other.into()),
            }
        }
        self.audit(
            &mut *tx,
            cmd,
            AuditActor::Human(approver),
            "approval.recorded",
            PortAuditDecision::Allow,
            &format!(
                "{} by {} as {}; allowlist {}; channel {:?}",
                cmd.verb.as_str(),
                auth.approver(),
                auth.designation(),
                auth.allowlist_version(),
                cmd.channel
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(created)
    }

    /// How many more distinct approvers the tier needs for the head that was approved.
    async fn approvals_missing(
        &self,
        cmd: &ApprovalCommand,
        request: &ApprovalRequest,
    ) -> Result<u32, ServiceError> {
        let d = &self.deps;
        let mut tx = d.store.begin(TenantScope::new(cmd.tenant)).await?;
        let valid = tx.valid_approvals(cmd.job, &request.pr_head).await?;
        tx.commit().await?;
        let required = d.policy.authority.required_approvals(request.tier);
        let counted = count_distinct(&valid, request.tier);
        Ok(required.saturating_sub(counted))
    }

    async fn audit(
        &self,
        tx: &mut dyn factory_ports::store::Tx,
        cmd: &ApprovalCommand,
        actor: AuditActor,
        action: &str,
        decision: PortAuditDecision,
        reason: &str,
    ) -> Result<(), ServiceError> {
        let d = &self.deps;
        tx.record_audit(NewAuditEvent {
            id: AuditEventId::from_uuid(d.ids.new_uuid()),
            actor,
            action: PortAuditAction::new(action).map_err(|_| ServiceError::Unavailable)?,
            subject: format!("job {}", cmd.job),
            decision,
            reason: reason.chars().take(900).collect(),
            policy_hash: d.policy_hash.clone(),
            job: Some(cmd.job),
            stage_run: Some(cmd.stage_run),
            correlation_id: CorrelationId::from_uuid(d.ids.new_uuid()),
        })
        .await?;
        Ok(())
    }

    /// Audits a refusal, and applies what the refusal means for the approvals and the evidence.
    async fn refuse(
        &self,
        cmd: &ApprovalCommand,
        refusal: &Refusal,
        allowlist_version: &str,
        drift: &[&'static str],
        request: &ApprovalRequest,
    ) -> Result<(), ServiceError> {
        let d = &self.deps;
        let mut tx = d.store.begin(TenantScope::new(cmd.tenant)).await?;
        let principal = tx.find_principal_by_github_user(cmd.sender.id).await?;
        let actor = match principal {
            Some(found) => AuditActor::Human(found.id),
            None => AuditActor::Anonymous(
                Slug::parse("approval-command").map_err(|_| ServiceError::Unavailable)?,
            ),
        };
        let sender = cmd.sender.id;
        self.audit(
            &mut *tx,
            cmd,
            actor,
            "approval.refused",
            PortAuditDecision::Deny,
            &format!(
                "{} {} refused: {}; sender {sender}; allowlist {allowlist_version}",
                cmd.verb.as_str(),
                request.pull_request,
                refusal.code()
            ),
        )
        .await?;
        // An approval that is already recorded stops counting when the world it was about
        // changed. Only a reason the store knows is written.
        let invalidate = match refusal {
            Refusal::HeadMoved => Some(ApprovalInvalidation::NewCommit),
            Refusal::BaseMoved => Some(ApprovalInvalidation::BaseMoved),
            Refusal::EvidenceDrift(names) => names.first().map(|name| invalidation_of(name)),
            _ => None,
        };
        if let Some(reason) = invalidate {
            tx.invalidate_approvals(cmd.job, reason).await?;
        }
        tx.commit().await?;
        // A change in the values the evidence is bound to (the base commit, the gate definitions,
        // the policy, the image) supersedes the runs that depend on it, whichever check noticed.
        if binding::is_drift(drift) {
            d.engine
                .apply_change(cmd.tenant, cmd.job, ArtifactChange::GateEvidenceBinding)
                .await
                .map_err(|_| ServiceError::Unavailable)?;
        }
        Ok(())
    }

    /// Called when the pull request changed on the code host (a push, a rebase): approvals that
    /// were about another head stop counting. Returns how many did.
    ///
    /// # Errors
    /// [`ServiceError::Unavailable`] when a source could not answer.
    pub async fn head_changed(
        &self,
        tenant: TenantId,
        job: factory_domain::ids::JobId,
        stage_run: StageRunId,
    ) -> Result<u32, ServiceError> {
        let d = &self.deps;
        let request = d.approvals.request(tenant, stage_run).await?;
        let git = Self::scope(&request, tenant, job)?;
        let pr = d
            .host
            .pull_request_state(
                &git,
                &PullRequestRef {
                    repo: git.repo.clone(),
                    number: request.pull_request,
                },
            )
            .await
            .map_err(host_unavailable)?;
        if pr.head_sha == commit_sha(&request.pr_head)? {
            return Ok(0);
        }
        let mut tx = d.store.begin(TenantScope::new(tenant)).await?;
        let changed = tx
            .invalidate_approvals(job, ApprovalInvalidation::NewCommit)
            .await?;
        tx.commit().await?;
        Ok(changed)
    }
}

fn host_unavailable(_: GitHostError) -> ServiceError {
    ServiceError::Unavailable
}

/// The distinct approvers whose approvals count for the tier: for the critical tier only a
/// security approver counts, as the tier row says.
fn count_distinct(valid: &[Approval], tier: RiskTier) -> u32 {
    let needs = if tier == RiskTier::Critical {
        Some(Designation::SecurityApprover.as_str())
    } else {
        None
    };
    let distinct: std::collections::BTreeSet<u64> = valid
        .iter()
        .filter(|a| a.decision == ApprovalDecision::Approve)
        .filter(|a| needs.is_none_or(|role| a.designation.as_str() == role))
        .map(|a| a.approver_github_user_id)
        .collect();
    u32::try_from(distinct.len()).unwrap_or(u32::MAX)
}
