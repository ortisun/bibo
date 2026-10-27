//! The decisions a person can take on a stage run, and the commands that control a job.
//!
//! A decision is a request, not a state change. The engine reads who is asking from the
//! [`Authority`](super::Authority), checks the roles that the transition table lists for the move,
//! evaluates the guard, and applies the move or refuses with a typed error that leaves the state
//! as it was. Text a person writes (an answer, a reason) is untrusted: it is stored as an artifact
//! and only its hash goes into an event.

use factory_domain::ids::{CausationId, JobId, PrincipalId, StageRunId, TenantId};
use factory_domain::values::{HumanText, Sha256Digest};
use factory_domain::vocabulary::StageKind;

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
/// override that they do not allow.
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
    },
    /// Lets a blocked stage run go again (`S17`).
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
