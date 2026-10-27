//! Initializes tracing and OpenTelemetry for the binaries and owns the span and attribute names.
//!
//! The conventions for everything in this crate are written in
//! `docs/observability/conventions.md`. The tables on that page and the constants here are
//! checked against each other by the tests.

pub mod names;
