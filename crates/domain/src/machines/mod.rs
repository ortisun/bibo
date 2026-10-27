//! Rules that sit on top of the state tables in [`state`](crate::state).
//!
//! The tables say which moves exist. This module says when a move is justified and what it
//! sets off. Everything here is a pure function of the values it is given: no database, no
//! clock, no random numbers. The engine reads the stored state, builds the small snapshot
//! types, calls these functions and applies the answer in one transaction.
//!
//! | Module | What it holds |
//! |---|---|
//! | [`snapshot`] | Read-only views of stored state that the rules read |
//! | [`limits`] | The rework cap (ADR 0009) and the count of rounds used |
//! | [`failure`] | The failure classes of an attempt and the attempt event for each |
//! | [`guards`] | The named guard predicates, evaluated against facts |
//! | [`retry`] | What a failed attempt does to its stage run: retry, ask a human, or fail |
//! | [`rework`] | Where a stage run that needs rework sends the work, and whether the cap allows it |
//! | [`invalidation`] | Which runs become stale when an upstream artifact changes |

pub mod failure;
pub mod guards;
pub mod invalidation;
pub mod limits;
pub mod retry;
pub mod rework;
pub mod snapshot;
