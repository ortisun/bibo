//! Read-only views of stored state, as the rules in this module read them.
//!
//! The engine loads rows, builds these small values and hands them in. Nothing here reads the
//! database or the clock. A snapshot says what the stored state was at one moment; it never
//! changes the state.

use crate::ids::StageRunId;
use crate::macros::string_enum;
use crate::state::{AttemptStatus, StageRunStatus};
use crate::vocabulary::{GateOutcome, StageKind};

string_enum! {
    /// Whether the sandbox of an attempt still exists.
    pub enum SandboxState("sandbox state") {
        /// The attempt ended before a sandbox was made.
        NeverCreated = "never_created",
        /// The sandbox exists.
        Up = "up",
        /// The sandbox was removed and the provider confirmed it.
        TornDown = "torn_down",
        /// The sandbox could not be confirmed gone and a leaked-resources alert was raised.
        Leaked = "leaked",
    }
}

/// One attempt of a job and its sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptSnapshot {
    /// Where the attempt stands.
    pub status: AttemptStatus,
    /// Whether its sandbox still exists.
    pub sandbox: SandboxState,
}

/// The result of one mandatory gate, as the stage gate reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateReportSnapshot {
    /// What the gate found.
    pub outcome: GateOutcome,
    /// For `NOT_APPLICABLE`: whether the reason is recorded.
    pub not_applicable_reason_recorded: bool,
}

string_enum! {
    /// What was recorded to clear a `BLOCKED` stage run (guard `G_BLOCK_DISPOSITIONS_RECORDED`).
    pub enum BlockDisposition("block disposition") {
        /// The capability probe was run again and passed.
        CapabilityReprobePassed = "capability_reprobe_passed",
        /// An authorized human accepted the residual risk and the policy allows it.
        OverrideAllowed = "override_allowed",
        /// A human decided that the work goes back for rework.
        ReworkDecision = "rework_decision",
    }
}

/// One stage run of a job, as the rules need to see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageRunSnapshot {
    /// The run.
    pub id: StageRunId,
    /// Which stage the run executes.
    pub kind: StageKind,
    /// Where the run stands.
    pub status: StageRunStatus,
    /// What was recorded for the run while it is `BLOCKED`, if anything.
    pub block_disposition: Option<BlockDisposition>,
}

impl StageRunSnapshot {
    /// A run with no block disposition recorded.
    #[must_use]
    pub const fn new(id: StageRunId, kind: StageKind, status: StageRunStatus) -> Self {
        Self {
            id,
            kind,
            status,
            block_disposition: None,
        }
    }
}
