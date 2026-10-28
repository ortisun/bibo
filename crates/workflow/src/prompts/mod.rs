//! The prompt assembler: where text that other people or programs wrote enters a model prompt.
//!
//! This module is under construction in this commit series; its documentation is completed with
//! the last increment.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod assemble;
mod block;
mod class;
mod error;
mod input;
mod limits;
mod manifest;
mod sanitize;
mod template;
mod verify;

pub use assemble::{Assembled, Assembler, AssemblyRequest, Part, Scope};
pub use class::ContentClass;
pub use error::{AssemblyError, TemplateError};
pub use input::{IndependentInput, Input, LineRange, Source, Trust};
pub use limits::Limits;
pub use manifest::{
    ContextManifest, Exclusion, ExclusionReason, InputRecord, Signal, TemplateRecord,
};
pub use template::{InputSpec, MAX_INPUTS, Template};
