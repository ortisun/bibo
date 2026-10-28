//! The scripted wiring: a stand-in for the composition roots, until they exist.
//!
//! It runs the real workflow engine over the testkit fakes: the in-memory store and artifact
//! store, the fake sandbox, the fake agent runtime and the scripted adversarial runtime (FX-ADV),
//! and the fake GitHub server (FX-GH). Every one of those labels itself a fake, so every piece of
//! evidence it returns says `test` mode.
//!
//! What the engine owns is real here: the stage runs, the attempts, the leases, the ledger and its
//! chain, the audit stream, the transitions and the rework rule. What the stage packages that are
//! not merged would produce (the specification, the plan, the documentation, the pull request) is
//! scripted, bound to the real identifiers, and labelled by the wiring name `scripted`.
//!
//! The engine's test harness (`crates/workflow/tests/support`) builds the engine from the fakes.
//! This module includes those files as they are, so that the scripted wiring and the engine's own
//! scenario tests drive one construction. If the engine package turns that harness into a public
//! testkit surface, the `#[path]` below goes away.

mod capture;
mod drive;
mod github;
mod snapshot;

#[path = "../../../../crates/workflow/tests/support/mod.rs"]
#[allow(clippy::pedantic, clippy::all, missing_docs, dead_code, unused_imports)]
mod support;

use std::path::Path;

use factory_testkit::fx::github::Protection;

use crate::check::Env;
use crate::evidence::{ProtectionFacts, RunEvidence};
use crate::runner::{Blocked, Wiring};
use crate::scenarios::Scenario;

pub use github::Remote;
use snapshot::Transitions;

/// The scripted wiring.
pub struct Scripted {
    pub(crate) transitions: Transitions,
    /// Changes the protection the fake remote gets. A test uses it to make the remote fail the
    /// preflight.
    pub(crate) weaken: Option<fn(&mut Protection)>,
}

impl Scripted {
    /// A scripted wiring for the repository at `root`.
    ///
    /// # Errors
    /// A sentence saying what could not be read.
    pub fn new(root: &Path) -> Result<Self, String> {
        let _env = Env::load(root)?;
        let path = root.join("docs/architecture/state-machine.json");
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        Ok(Self {
            transitions: Transitions::from_state_machine(&text)?,
            weaken: None,
        })
    }

    /// The same, with a remote whose protection is changed by `change`.
    #[must_use]
    pub fn with_weak_protection(mut self, change: fn(&mut Protection)) -> Self {
        self.weaken = Some(change);
        self
    }
}

impl Wiring for Scripted {
    fn name(&self) -> &'static str {
        "scripted"
    }

    fn real(&self) -> bool {
        false
    }

    fn protection(&mut self) -> Result<ProtectionFacts, Blocked> {
        let remote = Remote::new(self.protection_for_run());
        Ok(remote.protection())
    }

    fn run(&mut self, scenario: &Scenario) -> Result<RunEvidence, Blocked> {
        drive::run(self, scenario)
    }
}
