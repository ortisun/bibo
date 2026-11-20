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
//! | [`limits`] | The rework cap and the repair cap (ADR 0009, ADR 0010), and the count of rework rounds used |
//! | [`failure`] | The failure classes of an attempt and the attempt event for each |
//! | [`guards`] | The named guard predicates, evaluated against facts |
//! | [`retry`] | What a failed attempt does to its stage run: retry, ask a person, or fail. A limit asks a person; only a failure that retrying cannot fix fails the stage run. It also holds the attempt window, which starts again at each human answer |
//! | [`rework`] | Where a stage run that needs rework sends the work: the route of the stage, the defect class matrix for the four reviewed stages, and the targets a person may name. It also holds the cap check |
//! | [`invalidation`] | Which runs become stale when something they were built on changes: the five artifacts the pipeline produces, a new repository map, an edited request, and a moved value that the gate evidence is bound to |

pub mod failure;
pub mod guards;
pub mod invalidation;
pub mod limits;
pub mod retry;
pub mod rework;
pub mod snapshot;
