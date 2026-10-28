//! The Docker sandbox with its posture verifier and supervisor, and the host-side checkout
//! workspace. It is the only crate that starts containers or runs the version-control tool.

pub mod container;
pub mod process;

pub use process::SystemProcessRunner;
