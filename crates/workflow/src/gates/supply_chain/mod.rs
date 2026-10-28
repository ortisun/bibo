//! The dependency and supply chain gates of the validation stage.
//!
//! A change can bring new code into the build in four ways: a new dependency, a changed
//! lockfile, a changed place to fetch from, and code that runs while fetching or building. This
//! module judges all four from the files of the base commit and of the candidate, and from
//! commands that the supervisor ran in a sandbox. Nothing here asks the builder.
//!
//! # The order of a run ([`gate::run`])
//!
//! 1. [`integrity`] reads the dependency files of the **base commit** and of the candidate and
//!    compares them. Sources, checksums, versions, patches, the build configuration and the
//!    agreement between manifest and lockfile are checked. A violation stops the run: no
//!    sandbox is made.
//! 2. [`review`] sends every **new direct dependency** (a name absent from the base commit's
//!    lockfile) to the policy engine (`DependencyPolicy::decide`). Each needs a human, and the
//!    answer says which kind. Nothing is fetched until every one has a recorded decision
//!    ([`approval`]) bound to its exact name, version and checksum.
//! 3. [`run::fetch`] fetches in the `fetch_deps` sandbox with `cargo fetch` and
//!    `cargo metadata`, as the command sets allow. No repository code runs there. The licenses
//!    and the build code of every package that came in are read from the metadata.
//! 4. [`run::scan`] runs the audit tool and the SBOM tool in a fresh `verify` sandbox, which has
//!    no network. A tool that is not there blocks the gate ([`tools`]).
//! 5. [`report`] turns each result into a gate report. A gate that did not run is `BLOCKED`.
//!
//! | Module | Holds |
//! |---|---|
//! | [`toml`], [`version`] | a reader for the part of TOML and semver the files use, written to refuse what it does not know |
//! | [`model`], [`cargo`] | the ecosystem-neutral types and the Cargo reader |
//! | [`diff`], [`integrity`], [`findings`] | the lockfile difference and the checks over it |
//! | [`names`], [`facts`], [`licenses`] | the popular-name data, the registry facts, the license rule |
//! | [`approval`], [`review`] | the recorded human decision and the plan that depends on it |
//! | [`run`], [`tools`] | the two sandboxes and the readers of their output |
//! | [`report`], [`gate`] | the four reports and the whole run |
//!
//! # What is not here
//!
//! * Only Cargo is implemented. [`model::DependencyFormat`] is the seam for npm, pip and Go.
//! * The registry facts (does the name exist, when was it first published) come from a
//!   [`facts::RegistryMetadata`] that the composition root supplies. This crate has no network.
//! * The wiring into the validation stage is `stages::validation::supply`, which reads the
//!   dependency files of both commits from the object store and calls [`gate::run`] for a change
//!   that touches one. Everything the gate takes from outside the repository comes in through
//!   four seams the composition root supplies: [`approval::RecordedApprovals`],
//!   [`facts::RegistryMetadata`], [`facts::AdvisoryDatabase`] and the settings in
//!   `stages::validation::SupplyChainSettings` (internal names, the limit on the age of the
//!   advisory database, the SBOM rule).

pub mod approval;
pub mod cargo;
pub mod diff;
pub mod facts;
pub mod findings;
pub mod gate;
pub mod integrity;
pub mod licenses;
pub mod model;
pub mod names;
pub mod report;
pub mod review;
pub mod run;
pub mod toml;
pub mod tools;
pub mod version;
