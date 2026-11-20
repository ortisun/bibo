//! The decisions a person can take on a stage run, and the commands that control a job.
//!
//! A decision is a request, not a state change. The engine reads who is asking from the
//! [`Authority`](super::Authority), checks the roles that the transition table lists for the move,
//! evaluates the guard, and applies the move or refuses with a typed error that leaves the state
//! as it was. Text a person writes (an answer, a reason) is untrusted: it is stored as an artifact
//! and only its hash goes into an event.

use factory_domain::contracts::GateReport;
use factory_domain::ids::{CausationId, JobId, PrincipalId, StageRunId, TenantId};
use factory_domain::policy::authority::AuthorityPolicy;
use factory_domain::policy::decision::AuthorizedApproval;
use factory_domain::policy::solo::ConfirmationWord;
use factory_domain::values::{HumanText, Sha256Digest, Timestamp};
use factory_domain::vocabulary::{GateOutcome, StageKind};

/// Who is asking, for which tenant, under which command id.
///
/// The command id is the idempotency key. A command that arrives twice with the same id is applied
/// once, and the second is answered with `EngineError::Duplicate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Actor {
    /// The tenant the principal acts in.
    pub tenant: TenantId,
    /// The person.
    pub principal: PrincipalId,
    /// Identifies this request.
    pub command: CausationId,
}

/// What policy says about an override, as the policy evaluator computed it. The engine does not
/// evaluate policy files itself: these facts come from the caller, and the engine refuses an
/// override that they do not allow. A caller makes them with [`OverrideFacts::from_policy`] or
/// [`OverrideFacts::for_reports`], which read the policy, and does not write `policy_permits` by
/// hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverrideFacts {
    /// Policy permits an override for the code of this block.
    pub policy_permits: bool,
    /// The block is a security-class block, so a security approver must dispose of it.
    pub security_class: bool,
    /// The blocked gate is a mandatory gate of an active domain profile. No override applies to
    /// such a gate (INV-07).
    pub mandatory_of_active_profile: bool,
}

impl OverrideFacts {
    /// The facts of an override of blocks the policy has an opinion on, computed from the policy
    /// and not asserted by the caller. `blocks` are the (gate, block code) pairs that blocked the
    /// stage run. Policy permits the override only when there is at least one block and the
    /// policy lists none of them as a block no override may pass
    /// (`gate_integrity.non_overridable_blocks`); a stage run with no known block has nothing
    /// that policy could permit.
    ///
    /// `security_class` and `mandatory_of_active_profile` are facts about the blocked gate that
    /// the caller reads from the gate's definition and the active domain profile.
    #[must_use]
    pub fn from_policy(
        authority: &AuthorityPolicy,
        blocks: &[(&str, &str)],
        security_class: bool,
        mandatory_of_active_profile: bool,
    ) -> Self {
        Self {
            policy_permits: !blocks.is_empty()
                && blocks
                    .iter()
                    .all(|(gate, code)| authority.block_may_be_overridden(gate, code)),
            security_class,
            mandatory_of_active_profile,
        }
    }

    /// The same, for the gate reports of the stage run: every report that is `BLOCKED` is a block,
    /// with the code it carries. A blocked report that carries no code cannot be told apart from
    /// a block policy holds back, and counts as one.
    #[must_use]
    pub fn for_reports(
        authority: &AuthorityPolicy,
        reports: &[GateReport],
        security_class: bool,
        mandatory_of_active_profile: bool,
    ) -> Self {
        let mut permitted = true;
        let mut blocks = 0_usize;
        for report in reports
            .iter()
            .filter(|report| report.outcome == GateOutcome::Blocked)
        {
            blocks += 1;
            permitted &= report.blocked_reason.as_ref().is_some_and(|reason| {
                authority
                    .block_may_be_overridden(report.metadata.gate_id.as_str(), reason.code.as_str())
            });
        }
        Self {
            policy_permits: blocks > 0 && permitted,
            security_class,
            mandatory_of_active_profile,
        }
    }
}

/// A decision on a stage run that waits for a person or is blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Answers the question of a waiting stage run (`S13`). The answer is a new input of the
    /// stage and starts a new attempt window.
    Answer {
        /// The answer. Untrusted text.
        text: String,
        /// The answer raises a budget ceiling, which only an organization administrator may do.
        raises_budget_ceiling: bool,
    },
    /// Approves a waiting stage run (`S14`).
    Approve {
        /// The evidence digest the person saw: the hash of the last ledger entry.
        evidence_seen: Sha256Digest,
        /// Every open warning of the rule `translation-unfaithful` in the gate reports has a
        /// recorded decision of this person. The API sets it after it recorded them.
        warnings_decided: bool,
        /// The policy engine's proof for this approval, when the caller has one. The engine
        /// accepts an approval by the requester of the job only with a proof that carries the
        /// solo stamp and is the acting person's (ADR 0021), and then checks the solo fact again.
        /// `None` keeps the rule that the approver is not the requester.
        proof: Option<AuthorizedApproval>,
    },
    /// Rejects a waiting stage run (`S16`). The job ends as rejected.
    Reject {
        /// Why. Plain English.
        reason: HumanText,
    },
    /// Sends the work back to an earlier stage (`S15`).
    RequestRework {
        /// The stage that gets a new run. The table of human rework routes limits the choice.
        target: StageKind,
        /// What the person asks to be changed, when they said. The engine stores the text and
        /// links it to the run that is sent back, and the run that replaces it reads it with the
        /// reports of the gates (`ReworkContext::person_request`).
        instructions: Option<HumanText>,
    },
    /// Lets a blocked stage run go again (`S17`). Guard `G_BLOCK_CLEARED_RERUN` has three
    /// alternatives. The two facts below are the caller's. The third, that a person recorded the
    /// decision on a dependency that the stage run was waiting for, is read by the engine from what
    /// it stored (`Engine::record_dependency_decision`), so there is no flag to pass for it.
    UnblockRerun {
        /// The capability probe was run again and passed.
        capability_reprobe_passed: bool,
        /// The missing dependency is available now.
        dependency_now_available: bool,
    },
    /// Accepts the residual risk of a block and passes the stage run (`S18`). It never creates an
    /// assurance level.
    Override {
        /// Why the risk is accepted. Plain English.
        justification: HumanText,
        /// What policy allows.
        facts: OverrideFacts,
    },
}

/// What a decision taken alone in the solo mode carries for the engine's check of the wait and
/// the phrase (ADR 0021).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoloRequest {
    /// When the person asked: the time the database wrote the signed request. The wait is
    /// measured up to here.
    pub requested_at: Timestamp,
    /// The word of the confirmation phrase the request carried, if any.
    pub confirmation: Option<ConfirmationWord>,
}

/// A command that controls the whole job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobCommand {
    /// Stops new leases. Running attempts finish or time out (`J05`).
    Pause,
    /// Lets a paused job go on (`J06`).
    Resume,
    /// Cancels the job: attempts are told to stop, sandboxes come down (`J09`, `J10`).
    Cancel,
}

/// The stage run and job a decision is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subject {
    /// The job.
    pub job: JobId,
    /// The stage run.
    pub stage_run: StageRunId,
}
