//! The rework cap, the repair cap, and the count of rework rounds already used.
//!
//! ADR 0009 item 6 sets the default for rework: two rounds, then a human decides. ADR 0022 gives
//! the specification, the design, the code and the documentation each their own count. ADR 0010 sets the same default for repairs after an
//! invalid output. A project policy may lower a cap and may never raise it, because raising it is
//! a widening that needs a recorded human decision. So a cap is built with
//! [`ReworkCap::from_policy`] or [`RepairCap::from_policy`], which take the lower of the policy
//! value and the default, and no other constructor exists.

use crate::macros::string_enum;
use crate::vocabulary::StageKind;

/// The rework cap that applies when no policy lowers it (ADR 0009 item 6).
pub const DEFAULT_REWORK_CAP: u8 = 2;

/// The repair cap that applies when no policy lowers it (ADR 0010 decision 1).
pub const DEFAULT_REPAIR_CAP: u8 = 2;

string_enum! {
    /// Which count a rework round is charged to.
    ///
    /// Each phase of the pipeline that ends in an artifact a later phase is judged against has its
    /// own count, so rounds spent converging one artifact never use the rounds of the next one
    /// (ADR 0022). The count follows the stage the round targets, see [`for_target`](Self::for_target).
    pub enum ReworkTrack("rework track") {
        /// A re-run of `SPECIFICATION`: the clarify loop that ends when the specification is
        /// frozen. Policy key `max_specification_rework_iterations`.
        Specification = "specification",
        /// A re-run of `ARCHITECTURE` or `TASK_PLANNING`: the design that is judged against the
        /// frozen specification. Policy key `max_design_rework_iterations`.
        Design = "design",
        /// A re-run of `IMPLEMENTATION`, where validation and review send their findings. Policy
        /// key `max_rework_iterations`, the bound that `state-machine.md` names for
        /// `IMPLEMENTATION` re-runs.
        Code = "code",
        /// A re-run of `DOCUMENTING`. Policy key `max_documentation_rework_iterations`.
        Documentation = "documentation",
    }
}

/// How many counts there are: one for each [`ReworkTrack`].
const TRACKS: usize = 4;

impl ReworkTrack {
    /// The count that a rework round with this target stage is charged to.
    ///
    /// Only `SPECIFICATION`, `ARCHITECTURE`, `TASK_PLANNING`, `IMPLEMENTATION` and `DOCUMENTING`
    /// are targets in `state-machine.json` today. Every other stage is still given the count of
    /// its phase, so a route added later is bounded from its first round: the stages before the
    /// specification is frozen go to [`Specification`](Self::Specification), `DOMAIN_DISCOVERY`
    /// goes with the design it feeds, and every stage from `IMPLEMENTATION` on that is not
    /// `DOCUMENTING` goes to [`Code`](Self::Code).
    #[must_use]
    pub const fn for_target(target: StageKind) -> Self {
        match target {
            StageKind::Intake | StageKind::RepositoryIntelligence | StageKind::Specification => {
                ReworkTrack::Specification
            }
            StageKind::DomainDiscovery | StageKind::Architecture | StageKind::TaskPlanning => {
                ReworkTrack::Design
            }
            StageKind::Documenting => ReworkTrack::Documentation,
            StageKind::Implementation
            | StageKind::Validation
            | StageKind::Review
            | StageKind::DocumentationReview
            | StageKind::Delivery
            | StageKind::Approval
            | StageKind::Merge => ReworkTrack::Code,
        }
    }

    /// The place of this count in the arrays of [`ReworkLimits`] and [`ReworkLedger`].
    const fn index(self) -> usize {
        match self {
            ReworkTrack::Specification => 0,
            ReworkTrack::Design => 1,
            ReworkTrack::Code => 2,
            ReworkTrack::Documentation => 3,
        }
    }
}

/// How many rework rounds one count allows. Never above [`DEFAULT_REWORK_CAP`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReworkCap(u8);

impl ReworkCap {
    /// The cap with no policy override.
    pub const DEFAULT: Self = Self(DEFAULT_REWORK_CAP);

    /// The lower of the configured value and the default. A policy can tighten the cap, down to
    /// zero, and cannot loosen it.
    #[must_use]
    pub const fn from_policy(configured: u8) -> Self {
        if configured < DEFAULT_REWORK_CAP {
            Self(configured)
        } else {
            Self(DEFAULT_REWORK_CAP)
        }
    }

    /// The number of rounds.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl Default for ReworkCap {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How many repairs one attempt window allows after an invalid output. Never above
/// [`DEFAULT_REPAIR_CAP`].
///
/// A repair is a retry that follows an `INVALID_OUTPUT` failure, so it also counts as an attempt.
/// The policy value is `untrusted_content.structured_output.bounded_repair_attempts`. Like
/// [`ReworkCap`], a policy can lower it, down to zero, and cannot raise it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepairCap(u8);

impl RepairCap {
    /// The cap with no policy override.
    pub const DEFAULT: Self = Self(DEFAULT_REPAIR_CAP);

    /// The lower of the configured value and the default. A policy can tighten the cap and
    /// cannot loosen it.
    #[must_use]
    pub const fn from_policy(configured: u8) -> Self {
        if configured < DEFAULT_REPAIR_CAP {
            Self(configured)
        } else {
            Self(DEFAULT_REPAIR_CAP)
        }
    }

    /// The number of repairs.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl Default for RepairCap {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The caps of a job, one for each [`ReworkTrack`].
///
/// The default is [`DEFAULT_REWORK_CAP`] on every count. A cap is set only through
/// [`with_policy`](Self::with_policy), which takes the lower of the policy value and the default,
/// so no cap is ever above two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReworkLimits {
    caps: [ReworkCap; TRACKS],
}

impl Default for ReworkLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl ReworkLimits {
    /// Every count at [`DEFAULT_REWORK_CAP`].
    pub const DEFAULT: Self = Self {
        caps: [ReworkCap::DEFAULT; TRACKS],
    };

    /// Every count at the same policy value, lowered to the default if it is higher.
    #[must_use]
    pub const fn uniform(configured: u8) -> Self {
        Self {
            caps: [ReworkCap::from_policy(configured); TRACKS],
        }
    }

    /// These limits with the cap of `track` set from the policy value `configured`, lowered to
    /// the default if it is higher. The policy keys are `max_specification_rework_iterations`,
    /// `max_design_rework_iterations`, `max_rework_iterations` (code) and
    /// `max_documentation_rework_iterations`.
    #[must_use]
    pub const fn with_policy(self, track: ReworkTrack, configured: u8) -> Self {
        let mut caps = self.caps;
        caps[track.index()] = ReworkCap::from_policy(configured);
        Self { caps }
    }

    /// The cap of one count.
    #[must_use]
    pub const fn cap(self, track: ReworkTrack) -> ReworkCap {
        self.caps[track.index()]
    }
}

/// A rework round was asked for after the cap was used up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the {track} rework cap of {cap} rounds is reached; a human decides whether to go on")]
pub struct ReworkCapReached {
    /// The count that is full.
    pub track: ReworkTrack,
    /// Its cap.
    pub cap: u8,
}

/// How many rework rounds a job has used, for each count.
///
/// The only way to add a round is [`start_round`](Self::start_round), which refuses once the cap
/// is used up. So a ledger that starts within its cap stays within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReworkLedger {
    used: [u8; TRACKS],
}

impl ReworkLedger {
    /// This ledger with `rounds` used on `track`, as read back from storage. Every other count is
    /// unchanged.
    #[must_use]
    pub const fn with_used(self, track: ReworkTrack, rounds: u8) -> Self {
        let mut used = self.used;
        used[track.index()] = rounds;
        Self { used }
    }

    /// Rounds used on one count.
    #[must_use]
    pub const fn used(self, track: ReworkTrack) -> u8 {
        self.used[track.index()]
    }

    /// True when one more round would stay within the cap.
    #[must_use]
    pub const fn has_room(self, track: ReworkTrack, limits: ReworkLimits) -> bool {
        self.used(track) < limits.cap(track).get()
    }

    /// The ledger after one more round on `track`. No other count changes.
    ///
    /// # Errors
    /// Returns [`ReworkCapReached`] when the cap is already used up. The ledger is not changed.
    pub const fn start_round(
        self,
        track: ReworkTrack,
        limits: ReworkLimits,
    ) -> Result<Self, ReworkCapReached> {
        if !self.has_room(track, limits) {
            return Err(ReworkCapReached {
                track,
                cap: limits.cap(track).get(),
            });
        }
        // `has_room` proved that the count is below a cap of at most two, so adding one cannot
        // overflow.
        Ok(self.with_used(track, self.used(track) + 1))
    }
}

#[cfg(test)]
mod tests;
