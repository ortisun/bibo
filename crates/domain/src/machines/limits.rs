//! The rework cap and the count of rework rounds already used.
//!
//! ADR 0009 item 6 sets the default: two rounds, then a human decides. Code and documentation
//! each have their own count. A project policy may lower a cap and may never raise it, because
//! raising it is a widening that needs a recorded human decision. So the cap is built with
//! [`ReworkCap::from_policy`], which takes the lower of the policy value and the default, and no
//! other constructor exists.

use crate::macros::string_enum;
use crate::vocabulary::StageKind;

/// The rework cap that applies when no policy lowers it (ADR 0009 item 6).
pub const DEFAULT_REWORK_CAP: u8 = 2;

string_enum! {
    /// Which count a rework round is charged to.
    pub enum ReworkTrack("rework track") {
        /// A re-run of any stage other than `DOCUMENTING`.
        ///
        /// The bounds table in `state-machine.md` names only the `IMPLEMENTATION` re-runs, but
        /// the policy limit `max_rework_iterations` is per job. A re-run of `SPECIFICATION`,
        /// `ARCHITECTURE` or `TASK_PLANNING` also needs a bound, so it is charged here too.
        Code = "code",
        /// A re-run of `DOCUMENTING`.
        Documentation = "documentation",
    }
}

impl ReworkTrack {
    /// The count that a rework round with this target stage is charged to.
    #[must_use]
    pub const fn for_target(target: StageKind) -> Self {
        match target {
            StageKind::Documenting => ReworkTrack::Documentation,
            _ => ReworkTrack::Code,
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

/// The two caps of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReworkLimits {
    /// The cap for [`ReworkTrack::Code`].
    pub code: ReworkCap,
    /// The cap for [`ReworkTrack::Documentation`].
    pub documentation: ReworkCap,
}

impl ReworkLimits {
    /// Limits from the two policy values (`max_rework_iterations` and
    /// `max_documentation_rework_iterations`). Each is lowered to the default if it is higher.
    #[must_use]
    pub const fn from_policy(code: u8, documentation: u8) -> Self {
        Self {
            code: ReworkCap::from_policy(code),
            documentation: ReworkCap::from_policy(documentation),
        }
    }

    /// The cap of one count.
    #[must_use]
    pub const fn cap(self, track: ReworkTrack) -> ReworkCap {
        match track {
            ReworkTrack::Code => self.code,
            ReworkTrack::Documentation => self.documentation,
        }
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
    code: u8,
    documentation: u8,
}

impl ReworkLedger {
    /// A ledger read back from storage.
    #[must_use]
    pub const fn new(code: u8, documentation: u8) -> Self {
        Self {
            code,
            documentation,
        }
    }

    /// Rounds used on one count.
    #[must_use]
    pub const fn used(self, track: ReworkTrack) -> u8 {
        match track {
            ReworkTrack::Code => self.code,
            ReworkTrack::Documentation => self.documentation,
        }
    }

    /// True when one more round would stay within the cap.
    #[must_use]
    pub const fn has_room(self, track: ReworkTrack, limits: ReworkLimits) -> bool {
        self.used(track) < limits.cap(track).get()
    }

    /// The ledger after one more round on `track`.
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
        Ok(match track {
            ReworkTrack::Code => Self {
                code: self.code + 1,
                ..self
            },
            ReworkTrack::Documentation => Self {
                documentation: self.documentation + 1,
                ..self
            },
        })
    }
}

#[cfg(test)]
mod tests;
