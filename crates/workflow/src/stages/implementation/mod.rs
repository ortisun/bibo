//! The `IMPLEMENTATION` stage: a builder changes the code in a sandbox, and the factory ingests,
//! audits and commits the change on the host.
//!
//! Work package `s1-stage-implementation-and-review`.

pub mod evidence;
pub mod feedback;
pub mod input;
pub mod plan;
pub mod report;
pub mod scope;
pub mod seams;
