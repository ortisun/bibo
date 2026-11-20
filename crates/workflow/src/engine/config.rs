//! What the engine is told when it starts: the execution mode, the policy it runs under and the
//! bounds of `state-machine.md` ("Proposed bounds").
//!
//! The defaults here are the starting values of that table. Policy may lower a cap and never
//! raise it, which `ReworkLimits::from_policy` and `RepairCap::from_policy` enforce, so a config
//! built from them cannot hold a larger one.

use std::collections::BTreeSet;
use std::time::Duration;

use factory_domain::machines::limits::{RepairCap, ReworkLimits};
use factory_domain::policy::solo::SoloRules;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::{ExecutionMode, StageKind};

use super::error::EngineError;

/// How long a lease lasts. The lease is renewed by every heartbeat (state-machine.md, lease rules).
pub const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(60);

/// How often a running attempt renews its lease. Well inside the lease, so one lost heartbeat
/// does not lose the lease.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// How long a cancelled attempt has to tear its sandbox down before the sweeper forces it.
pub const DEFAULT_TEARDOWN_GRACE: Duration = Duration::from_secs(30);

/// The most stage runs one claim call leases.
pub const DEFAULT_CLAIM_BATCH: u32 = 8;

/// The `max_attempts` the engine gives every stage run it creates (`NewStageRun::max_attempts`):
/// the largest value the port accepts. Two limits apply to the attempts of a stage run, and they
/// have different owners (INV-10).
///
/// * **The stage contract decides.** Its `max_attempts` (1 to 10) is the limit that turns a failed
///   attempt into a retry or a question for a person. The engine counts it from the last human
///   answer (`Timeline`, which reads the answers from the store). The contract is resolved from
///   what the upstream stages produced, after the run exists, and the port has no call that sets
///   `max_attempts` of an existing run, so the store cannot hold the contract's number.
/// * **The store backstops.** `start_attempt` refuses attempt `n` when
///   `n - attempts_before_last_answer > max_attempts`. The database sets
///   `attempts_before_last_answer` itself when a person answers (`S13`), so this limit also counts
///   from the last answer: a person who answers gets a fresh window from the store as well, and
///   the store never refuses the first attempts after an answer.
///
/// The contract's window holds at most ten failed attempts, and the attempts that are not failures
/// (a success, which ends the window, or a cancellation, which replaces the run) add at most a few
/// more, so the contract's limit is always reached long before 20. The store's refusal
/// (`Deferral::AttemptLimit`) is therefore a sign of a bug in the engine and never a normal stop.
pub const STORE_ATTEMPT_CEILING: u8 = 20;

/// What one job may spend, in millionths of a US dollar: 25 dollars
/// (`policies/security.yaml`, `budgets.hard_ceilings.per_job.max_usd`).
pub const DEFAULT_JOB_BUDGET_MICRO_USD: u64 = 25_000_000;

/// The share of a ceiling, in percent, at which a threshold audit record is written
/// (`budgets.thresholds.warn_at_fraction`).
pub const DEFAULT_BUDGET_WARN_PERCENT: u64 = 80;

/// The gate and the block code of the block that no override may pass whatever the policy says
/// elsewhere: a new direct dependency with no recorded decision. It is the entry the policy file
/// must list (`gate_integrity.non_overridable_blocks`) and the engine refuses to build without; the
/// engine keeps it as the floor of [`EngineConfig::non_overridable_blocks`].
pub const UNRESOLVED_DEPENDENCY_REVIEW: (&str, &str) = ("dependency-review", "policy_unresolvable");

/// The stage kinds of Slice 1, in pipeline order. `MERGE` is not implemented and is disabled by
/// default (state-machine.md, pipeline table).
pub const SLICE_ONE_SCOPE: [StageKind; 13] = [
    StageKind::Intake,
    StageKind::RepositoryIntelligence,
    StageKind::Specification,
    StageKind::DomainDiscovery,
    StageKind::Architecture,
    StageKind::TaskPlanning,
    StageKind::Implementation,
    StageKind::Validation,
    StageKind::Review,
    StageKind::Documenting,
    StageKind::DocumentationReview,
    StageKind::Delivery,
    StageKind::Approval,
];

/// The settings of one engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfig {
    /// Production refuses every fake adapter and every fake record. Test mode allows them and
    /// labels the evidence they make (invariant INV-08).
    pub mode: ExecutionMode,
    /// The hash of the policy bundle in force. It goes on every audit event and every approval.
    pub policy_hash: Sha256Digest,
    /// The stage kinds a job runs, in pipeline order. A job completes when every one of them has
    /// a passed or a skipped run (`G_PIPELINE_SCOPE_COMPLETE`).
    pub scope: Vec<StageKind>,
    /// How long a claim or a heartbeat extends a lease.
    pub lease_ttl: Duration,
    /// How often a running attempt renews its lease.
    pub heartbeat_interval: Duration,
    /// The grace period for tearing down a cancelled attempt.
    pub teardown_grace: Duration,
    /// The rework caps. Never above two (ADR 0009 item 6).
    pub rework_limits: ReworkLimits,
    /// The repair cap after an invalid output. Never above two (ADR 0010).
    pub repair_cap: RepairCap,
    /// The most stage runs one claim call leases.
    pub claim_batch: u32,
    /// What one job may spend across all its attempts, in millionths of a US dollar. When it is
    /// spent, no retry or rework round starts and a person decides.
    pub job_budget_micro_usd: u64,
    /// The share of a ceiling at which the engine records a threshold audit event.
    pub budget_warn_percent: u64,
    /// The blocks, as (gate, block code), that no override may pass
    /// (`gate_integrity.non_overridable_blocks`). The engine reads the gate and the code of a
    /// block from the event it stored when the stage run blocked, and refuses an override of a
    /// stage run any of whose blocks is listed here, whatever facts the caller hands in. The
    /// default holds the block of an unresolved dependency review; a composition root adds the
    /// entries of the policy and never takes this one away.
    pub non_overridable_blocks: BTreeSet<(String, String)>,
    /// The rules of the solo mode (ADR 0021), which the engine checks again when it commits a
    /// decision the requester took alone. Off by default; a composition root sets the policy's
    /// with [`EngineConfig::with_solo`].
    pub solo: SoloRules,
}

impl EngineConfig {
    /// The Slice 1 defaults for `mode` under the policy with hash `policy_hash`.
    #[must_use]
    pub fn new(mode: ExecutionMode, policy_hash: Sha256Digest) -> Self {
        Self {
            mode,
            policy_hash,
            scope: SLICE_ONE_SCOPE.to_vec(),
            lease_ttl: DEFAULT_LEASE_TTL,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            teardown_grace: DEFAULT_TEARDOWN_GRACE,
            rework_limits: ReworkLimits::default(),
            repair_cap: RepairCap::default(),
            claim_batch: DEFAULT_CLAIM_BATCH,
            job_budget_micro_usd: DEFAULT_JOB_BUDGET_MICRO_USD,
            budget_warn_percent: DEFAULT_BUDGET_WARN_PERCENT,
            non_overridable_blocks: BTreeSet::from([(
                UNRESOLVED_DEPENDENCY_REVIEW.0.to_owned(),
                UNRESOLVED_DEPENDENCY_REVIEW.1.to_owned(),
            )]),
            solo: SoloRules::disabled(),
        }
    }

    /// Adds blocks that no override may pass. The floor stays: this adds and never removes.
    /// The same config with the rules of the solo mode of the policy.
    #[must_use]
    pub fn with_solo(mut self, solo: SoloRules) -> Self {
        self.solo = solo;
        self
    }

    #[must_use]
    pub fn with_non_overridable_blocks(
        mut self,
        blocks: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        self.non_overridable_blocks.extend(blocks);
        self
    }

    /// Checks the settings the engine relies on.
    ///
    /// # Errors
    /// Returns [`EngineError::Config`] naming the first rule that is broken: an empty scope, a
    /// scope that repeats a stage or is out of pipeline order, a heartbeat that is not shorter
    /// than the lease, or a zero batch.
    pub fn validate(&self) -> Result<(), EngineError> {
        if self.scope.is_empty() {
            return Err(EngineError::Config("the pipeline scope lists no stage"));
        }
        let in_order = self
            .scope
            .windows(2)
            .all(|pair| position(pair[0]) < position(pair[1]));
        if !in_order {
            return Err(EngineError::Config(
                "the pipeline scope must list each stage once, in pipeline order",
            ));
        }
        if self.heartbeat_interval.is_zero() || self.heartbeat_interval >= self.lease_ttl {
            return Err(EngineError::Config(
                "the heartbeat interval must be above zero and shorter than the lease",
            ));
        }
        if self.claim_batch == 0 {
            return Err(EngineError::Config("the claim batch must be above zero"));
        }
        Ok(())
    }
}

/// The place of a stage in the pipeline order.
pub(crate) fn position(kind: StageKind) -> usize {
    StageKind::ALL
        .iter()
        .position(|candidate| *candidate == kind)
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> EngineConfig {
        EngineConfig::new(ExecutionMode::Test, Sha256Digest::of(b"policy"))
    }

    #[test]
    fn the_defaults_are_the_bounds_table() {
        let config = config();
        assert_eq!(config.lease_ttl, Duration::from_secs(60));
        assert_eq!(config.heartbeat_interval, Duration::from_secs(15));
        assert_eq!(config.teardown_grace, Duration::from_secs(30));
        assert_eq!(config.rework_limits.code.get(), 2);
        assert_eq!(config.rework_limits.documentation.get(), 2);
        assert_eq!(config.repair_cap.get(), 2);
        assert_eq!(config.scope.len(), 13);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn merge_is_not_in_the_slice_one_scope() {
        assert!(!SLICE_ONE_SCOPE.contains(&StageKind::Merge));
    }

    #[test]
    fn a_scope_out_of_order_or_empty_is_refused() {
        let mut config = config();
        config.scope = vec![StageKind::Review, StageKind::Intake];
        assert!(matches!(config.validate(), Err(EngineError::Config(_))));
        config.scope = Vec::new();
        assert!(matches!(config.validate(), Err(EngineError::Config(_))));
        config.scope = vec![StageKind::Intake, StageKind::Intake];
        assert!(matches!(config.validate(), Err(EngineError::Config(_))));
    }

    #[test]
    fn a_heartbeat_slower_than_the_lease_is_refused() {
        let mut config = config();
        config.heartbeat_interval = config.lease_ttl;
        assert!(matches!(config.validate(), Err(EngineError::Config(_))));
        config.heartbeat_interval = Duration::ZERO;
        assert!(matches!(config.validate(), Err(EngineError::Config(_))));
    }
}
