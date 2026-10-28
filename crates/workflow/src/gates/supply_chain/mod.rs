//! The dependency and supply chain gates of the validation stage.
//!
//! A change can bring new code into the build in four ways: a new dependency, a changed
//! lockfile, a changed place to fetch from, and code that runs while fetching or building. This
//! module judges them from the files of the base commit and of the candidate, and from commands
//! that the supervisor ran in a sandbox. Nothing here asks the builder.
//!
//! This increment holds the pure part: [`integrity`] reads the dependency files of both commits
//! and compares them. Only Cargo is implemented; [`model::DependencyFormat`] is the seam for npm,
//! pip and Go.

pub mod approval;
pub mod cargo;
pub mod diff;
pub mod facts;
pub mod findings;
pub mod integrity;
pub mod licenses;
pub mod model;
pub mod names;
pub mod review;
pub mod toml;
pub mod tools;
pub mod version;
