//! Everything that turns a sandbox spec into Docker objects and reads them back: the typed
//! `docker` client, the image catalog, the allow-list mapping from a spec to `docker create`
//! arguments, the posture verifier, names and labels, and the job token file.

pub mod args;
pub mod docker;
pub mod images;
pub mod names;
pub mod posture;
mod posture_args;
pub mod token;
