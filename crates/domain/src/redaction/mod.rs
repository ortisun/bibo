//! Secret redaction. Work in progress: the module is built up in steps.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![allow(dead_code)]

mod automaton;
mod encodings;
mod terminal;

pub use encodings::Encoding;
