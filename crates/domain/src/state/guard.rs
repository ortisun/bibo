//! Guards and actors named by `docs/architecture/state-machine.json`.
//!
//! A guard is a condition that must hold before the engine applies a transition. This crate
//! names the guards and states which transition each one belongs to. It does not evaluate them,
//! because every guard needs facts that live outside the domain (the database, the clock, policy
//! files). The workflow crate evaluates a guard and then asks the state machine to apply the
//! transition. The doc comment on each guard is the wording from the file.
//!
//! This file was written from the JSON. The
//! conformance test `tests/state_machine_conformance.rs` compares every name with the file.

use crate::macros::string_enum;

string_enum! {
    /// Who may request a transition. Every transition is applied by the engine in one database
    /// transaction. The actor only says who may ask for it.
    pub enum Actor("state machine actor") {
        /// The workflow use-case layer. The only component that writes a status, always inside one database transaction. Every transition in this file is applied by the engine; the actor column only says who may request it.
        Engine = "engine",
        /// A process that holds an attempt lease. May request transitions for its own attempt only, and only with the current lease epoch.
        Worker = "worker",
        /// The timer tick inside the engine. Acts on deadlines, lease expiry and retry back-off.
        Sweeper = "sweeper",
        /// The deterministic gate evaluator called by the engine while a stage run is GATING. Reads evidence, never agent prose.
        Gate = "gate",
        /// The human who submitted the request. Must appear on the tenant's named requester allowlist in protected configuration. Holding a GitHub role is not enough.
        Requester = "requester",
        /// A human with operational rights on the tenant: pause, resume, cancel, unblock, grant budget.
        Operator = "operator",
        /// A human with the approval role defined by the tenant approval policy.
        Approver = "approver",
        /// A human on the explicit security approver list kept in protected central configuration. Required to dispose of a security-class block. Matches the role of the same name in policies/approval.yaml.
        SecurityApprover = "security_approver",
        /// A human organization administrator. May raise a budget above its ceiling, raise autonomy, and enable anything that is off by default. Matches policies/approval.yaml.
        OrgAdmin = "org_admin",
    }
}

string_enum! {
    /// A named condition on a transition.
    pub enum Guard("state machine guard") {
        /// The requester is on the tenant's named requester allowlist in protected configuration, the tenant is within its job quota, the repository is registered and enabled, the repository passed the protection preflight (otherwise the job may only run at autonomy level L0), policy allows this class of request, and neither the repository nor the organization has reached a ceiling of its day (budgets.hard_ceilings.per_repo_day and per_org_day).
        AdmissionOk = "G_ADMISSION_OK",
        /// The requester is not on the allowlist, the quota is exceeded, the repository is not registered or is disabled, policy forbids this class of request, or the repository or the organization has reached a ceiling of its day or its usage could not be read. The reason is recorded and no reply reveals which test failed.
        AdmissionDenied = "G_ADMISSION_DENIED",
        /// At least one stage run of the job is WAITING_FOR_HUMAN.
        AnyStageWaiting = "G_ANY_STAGE_WAITING",
        /// No stage run of the job is WAITING_FOR_HUMAN.
        NoStageWaiting = "G_NO_STAGE_WAITING",
        /// The principal holds the operator role on the tenant.
        ActorMayPause = "G_ACTOR_MAY_PAUSE",
        /// At least one stage run of the job is BLOCKED.
        AnyStageBlocked = "G_ANY_STAGE_BLOCKED",
        /// Every BLOCKED stage run has a recorded disposition: capability re-probe passed, or an allowed override, or a rework decision.
        BlockDispositionsRecorded = "G_BLOCK_DISPOSITIONS_RECORDED",
        /// The principal is the requester of the job or holds the operator role.
        ActorMayCancel = "G_ACTOR_MAY_CANCEL",
        /// Every attempt of the job is in a terminal state and every sandbox has been torn down or flagged as leaked.
        AllAttemptsTerminal = "G_ALL_ATTEMPTS_TERMINAL",
        /// The newest run of a stage kind in the job's scope is FAILED (by S06, S12 or S16), no newer run replaces it, and no rework route or retry budget remains; or a job-level hard limit was reached under a policy that says fail. The engine builds the facts from the listing of the job's stage runs, so a rework that created a newer run first leaves the guard unmet.
        Unrecoverable = "G_UNRECOVERABLE",
        /// The intake decision is decline, or an authorized approver recorded a reject decision.
        RejectionRecorded = "G_REJECTION_RECORDED",
        /// Every stage kind in the job's configured scope has a run that is PASSED, or SKIPPED because a recorded rule says the stage does not apply, and that run is not superseded; the approval decision is approve; and the evidence ledger hash chain verifies.
        PipelineScopeComplete = "G_PIPELINE_SCOPE_COMPLETE",
        /// Every required upstream stage run is PASSED, or SKIPPED because a recorded rule says the stage does not apply, and is not superseded. Every consumed artifact hash equals the current version (a skipped stage produced none, and the stage contract records the skip rule instead of a hash). The stage contract resolved and validated against its schema.
        UpstreamPassed = "G_UPSTREAM_PASSED",
        /// A deterministic rule, a domain profile or a policy states that the stage does not apply. The rule and its inputs are recorded in the ledger. An agent opinion is never sufficient.
        NotApplicableDecided = "G_NOT_APPLICABLE_DECIDED",
        /// The stage run is READY at the version the claim read, the job is ACTIVE, not_before has passed by the database clock, the concurrency quota allows it, and the runtime capability check passed. The store makes the check and the move one atomic step (start_attempt), so two workers cannot both pass it.
        LeaseAcquired = "G_LEASE_ACQUIRED",
        /// The attempt succeeded and its output validates against the stage outputs schema, and the output artifact hash is stored.
        OutputSchemaValid = "G_OUTPUT_SCHEMA_VALID",
        /// The failure class is retryable under the stage contract, the attempts used since the last human answer are below max_attempts, the budget has room for another attempt, and, after INVALID_OUTPUT, no more than two repairs have been made (a repair is a retry that follows an invalid-output failure; the cap comes from policy and can only be lowered).
        RetryAllowed = "G_RETRY_ALLOWED",
        /// Retrying cannot help: the failure class is POLICY_DENIED or INTERNAL, or the stage contract does not list it in retry_on. BUDGET_EXHAUSTED is not covered here, because a budget limit asks a human (S07). Reaching the attempt limit is not covered either, because an attempt limit asks a human (S07).
        FailureNonretryable = "G_FAILURE_NONRETRYABLE",
        /// A budget limit was hit (the failure class is BUDGET_EXHAUSTED, or a retry would be allowed in every other way but the budget has no room), the attempt limit or the repair cap was reached on a failure class the stage contract lists as retryable, the agent returned a structured needs_human request, the stagnation detector fired, or policy requires a human decision here.
        EscalationRequired = "G_ESCALATION_REQUIRED",
        /// The gate decision is PASS and is persisted, every acceptance criterion of the stage contract has a ledger entry, and every mandatory gate report is PASSED or NOT_APPLICABLE with a recorded reason. No gate report is BLOCKED.
        GatePassEvidenced = "G_GATE_PASS_EVIDENCED",
        /// The verdict is CHANGES_REQUIRED or a deterministic gate FAILED, the rework rounds used on the count of the target stage are below its cap of two, the failing set differs from the previous round, and budget remains. The specification (SPECIFICATION), the design (ARCHITECTURE and TASK_PLANNING), the code (IMPLEMENTATION) and the documentation (DOCUMENTING) each have their own count, so rounds on one never use the rounds of another (ADR 0022). After the second round on a count a human decides.
        ReworkAllowed = "G_REWORK_ALLOWED",
        /// The verdict is NEEDS_HUMAN, or the rework limit, the stagnation detector or a budget limit was reached, or the gate itself is a human gate, or a finding that justifies the verdict has a defect class that only a person can decide (specification, or policy; see defect_routing).
        NeedsHumanVerdict = "G_NEEDS_HUMAN_VERDICT",
        /// The verdict is BLOCK, a mandatory gate could not run (tool unavailable or probe failed), or a deterministic check detected a policy violation. A reviewer's finding with defect class policy asks a person instead (S10).
        BlockingCondition = "G_BLOCKING_CONDITION",
        /// The gate FAILED and the stage has no rework route, for example an intake record that is still invalid after bounded repair.
        GateFailedNoRework = "G_GATE_FAILED_NO_REWORK",
        /// A human answer, clarification, approval of residual input or budget extension is recorded with the principal and becomes a new input hash for the stage. It also starts a new attempt window: attempts and repairs are counted from the answer. A budget extension that raises a ceiling is accepted only from an org_admin.
        AnswerRecorded = "G_ANSWER_RECORDED",
        /// The decision is approve, the principal holds the role the approval policy requires for this stage and risk tier, the evidence digest the human saw equals the current evidence digest, and every warning of the rule translation-unfaithful in the gate reports of that evidence has a recorded human decision.
        ApproverAuthorized = "G_APPROVER_AUTHORIZED",
        /// The principal holds the approver or operator role and the rework rounds used on the count of the target the person names are below its cap of two (the four counts of G_REWORK_ALLOWED). The stagnation detector does not apply to human requests. After the second round on a count a human must choose to continue, with the decision recorded.
        HumanReworkAllowed = "G_HUMAN_REWORK_ALLOWED",
        /// An authorized approver recorded a reject decision with a reason.
        HumanRejected = "G_HUMAN_REJECTED",
        /// The capability re-probe passed or the missing dependency is now available, so the stage can run again.
        BlockClearedRerun = "G_BLOCK_CLEARED_RERUN",
        /// Policy permits an override for this block code, the principal holds the required role (security_approver for security-class blocks), a justification is recorded, and the blocked gate is not a mandatory gate of an active domain profile. An override records accepted residual risk. It never creates an assurance level claim.
        OverridePermitted = "G_OVERRIDE_PERMITTED",
        /// The stage run has no attempt in STARTING, RUNNING or CANCELLING.
        NoActiveAttempt = "G_NO_ACTIVE_ATTEMPT",
        /// A consumed upstream artifact was superseded by a newer version, an upstream stage run was reworked, or an external change listed in the invalidation table happened (the source request was edited after the intake snapshot, or a value bound to gate evidence changed).
        UpstreamInvalidated = "G_UPSTREAM_INVALIDATED",
        /// The sandbox provider returned a session for this attempt, which means it created the container, read its posture back, found every part equal to the spec and the policy, started it and passed the runtime self-check. The tool grants that policy approved are recorded in the audit log, the runtime probe of this attempt supports every capability the stage needs, and the lease epoch is current.
        SandboxProvisioned = "G_SANDBOX_PROVISIONED",
        /// The epoch sent by the worker equals the stored epoch and now is not past lease_expires_at.
        LeaseEpochCurrent = "G_LEASE_EPOCH_CURRENT",
        /// The epoch sent by the worker equals the stored epoch.
        EpochCurrent = "G_EPOCH_CURRENT",
        /// Now is past the attempt deadline.
        DeadlinePassed = "G_DEADLINE_PASSED",
        /// Now is past lease_expires_at and no heartbeat arrived.
        LeaseExpired = "G_LEASE_EXPIRED",
        /// The attempt is not terminal and the job is CANCELLING or the stage run is being superseded.
        CancelAllowed = "G_CANCEL_ALLOWED",
        /// The sandbox no longer exists, confirmed by the sandbox provider.
        SandboxGone = "G_SANDBOX_GONE",
        /// The teardown grace period elapsed. The sandbox is force-killed and a leaked_resources alert is raised if it cannot be confirmed gone.
        TeardownDeadlinePassed = "G_TEARDOWN_DEADLINE_PASSED",
        /// Every task this node depends on is SUCCEEDED.
        TaskDepsSucceeded = "G_TASK_DEPS_SUCCEEDED",
        /// The IMPLEMENTATION attempt picked this task as the next one in topological order.
        TaskStartedByAttempt = "G_TASK_STARTED_BY_ATTEMPT",
        /// A commit exists for the task, changed paths are inside the task's owned files, no protected path changed, and the per-task checks passed.
        TaskEvidenceRecorded = "G_TASK_EVIDENCE_RECORDED",
        /// The task retry count is below the per-task limit and the stage budget has room.
        TaskRetryAllowed = "G_TASK_RETRY_ALLOWED",
        /// The attempt ended because something the stage cannot work without is missing or unsafe, not because the work failed: the container runtime is unreachable, the image is not on the host, the posture check found a difference, the spec was weaker than the policy, a required tool or runtime capability is absent, or the policy file could not be loaded. The cause is recorded. Retrying with the same settings cannot help, and trying other settings is forbidden.
        EnvironmentBlocked = "G_ENVIRONMENT_BLOCKED",
        /// The stage run is an INTAKE run created after an external change to the source request, and the hash of the current original request differs from the hash the requester authorized; or policy asks the requester to confirm before any agent reads the text. No attempt starts and no agent reads the new text until a person answers.
        ReauthorizationRequired = "G_REAUTHORIZATION_REQUIRED",
    }
}
