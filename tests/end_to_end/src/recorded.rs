//! The `composed-test` wiring: it replays a recording that the composed pipeline made.
//!
//! The scenario is not run here. The test `apps/api/tests/e2e_scenarios.rs` ran it through the
//! real engine, the real API server on loopback, the worker hook and a real PostgreSQL, and wrote a
//! recording (see [`crate::recording`]). This wiring loads the recording, lets the runner check its
//! integrity, and hands the evidence to the assertions. It never claims real adapters: `real()` is
//! false, so a scenario that is defined for real adapters (E1 and E2) is `BLOCKED` on it.
//!
//! # What this wiring cannot judge
//!
//! [`GAPS`] lists the checks that read a thing the composed test rig does not produce. Each has a
//! reason, and a scenario that has one is `BLOCKED` on it, never passed. The list is here, in the
//! source, so that a reviewer sees what is not judged. A recording cannot add to it.

use std::path::Path;

use crate::check::Verdict;
use crate::evidence::{ProtectionFacts, RequiredCheckFacts, RunEvidence};
use crate::recording::{self, Loaded, Missing, Transitions, WIRING};
use crate::runner::{Blocked, Wiring};
use crate::scenarios::Scenario;

/// The checks that the composed test rig cannot judge: `(scenario, check, why)`.
///
/// The list is empty: the fake change host of the rig now mints a labelled token for each job, kind
/// of token, repository and permission set, so A10 is judged from tokens that are recorded (SF-04),
/// and the playbook can carry an agent that obeys the hostile text, so `E4.agent-denials` is judged
/// from attempts that were made (SF-05). What stays out of reach of the rig is the enforcement
/// itself, which belongs to the permission system of the coding tool and to the container; the
/// mode file of each recording says so.
pub const GAPS: [(&str, &str, &str); 0] = [];

/// A wiring over one scenario's recording.
pub struct Recorded {
    scenario: &'static str,
    loaded: Result<Loaded, Missing>,
}

impl Recorded {
    /// Loads the recording of `scenario` below `root`.
    ///
    /// # Errors
    /// A sentence saying what could not be read.
    pub fn new(root: &Path, scenario: &'static str) -> Result<Self, String> {
        let path = root.join("docs/architecture/state-machine.json");
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let transitions = Transitions::from_state_machine(&text)?;
        Ok(Self {
            scenario,
            loaded: recording::load(root, scenario, &transitions),
        })
    }

    fn loaded(&self) -> Result<&Loaded, Blocked> {
        self.loaded
            .as_ref()
            .map_err(|missing| Blocked::because(missing.0.clone()))
    }
}

impl Wiring for Recorded {
    fn name(&self) -> &'static str {
        WIRING
    }

    fn real(&self) -> bool {
        false
    }

    fn protection(&mut self) -> Result<ProtectionFacts, Blocked> {
        let loaded = self.loaded()?;
        let evidence = loaded.evidence.as_ref().ok_or_else(|| {
            Blocked::because(
                "the recording cannot be read, so the protection of the remote is unknown",
            )
        })?;
        // The remote of the composed rig reports its protection through the same port the real
        // code host does. A recording that holds none cannot be judged by the preflight.
        let protection = evidence
            .github
            .protection
            .clone()
            .unwrap_or(ProtectionFacts {
                require_pull_request: false,
                required_approvals: 0,
                required_checks: Vec::<RequiredCheckFacts>::new(),
                dismiss_stale_reviews: false,
                enforce_admins: false,
                allow_force_pushes: false,
                allow_deletions: false,
                require_code_owner_review: false,
                app_may_bypass: false,
            });
        Ok(protection)
    }

    fn integrity(&mut self, _scenario: &Scenario) -> Vec<Verdict> {
        match &self.loaded {
            Ok(loaded) => loaded.verdicts.clone(),
            Err(_) => Vec::new(),
        }
    }

    fn unevidenced(&self, scenario: &Scenario) -> Vec<(&'static str, &'static str)> {
        GAPS.iter()
            .filter(|(id, _, _)| *id == scenario.id)
            .map(|(_, check, why)| (*check, *why))
            .collect()
    }

    fn run(&mut self, scenario: &Scenario) -> Result<RunEvidence, Blocked> {
        debug_assert_eq!(scenario.id, self.scenario);
        let loaded = self.loaded()?;
        loaded.evidence.clone().ok_or_else(|| {
            Blocked::because("the recording could not be read, so there is no evidence")
        })
    }
}
