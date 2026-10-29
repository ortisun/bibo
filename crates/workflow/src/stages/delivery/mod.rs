//! The delivery stage: the evidence becomes a draft pull request that a person can judge.
//!
//! The stage reads stored, typed documents of the stages before it, checks that they still
//! describe the world, writes an evidence manifest, pushes the factory branch, opens a **draft**
//! pull request in plain English and publishes the gate results as check runs. It never merges,
//! never marks a pull request ready and never deploys: the `ChangeHost` port has no such call.
//!
//! # The order of a run
//!
//! 1. The contract names every document the stage reads, by hash, with the hash of the policy
//!    bundle ([`contract`]). A document an earlier stage did not produce blocks the stage.
//! 2. The documents are read back and parsed ([`input`]).
//! 3. The values the gate reports are bound to are compared with the world: the base branch is
//!    resolved again, the gate definitions and the image are read again, the policy hash is the
//!    one in the contract. A difference is reported to the engine through [`EvidenceDrift`],
//!    which supersedes the runs that depend on the evidence (ADR 0010), and nothing is pushed.
//! 4. The change is measured from the job's object store, from the base to the commit that will
//!    be pushed (the documentation commit when there is one), and the manifest is built
//!    ([`manifest`]).
//! 5. The title and body are written from typed evidence ([`pr`], [`text`]) and read by the
//!    readability gate. Text that is refused stops the stage before the host is touched.
//! 6. The branch is pushed, the draft pull request is opened and read back, and the check runs
//!    are published ([`publish`], [`checks`]). Each step is safe to repeat.
//! 7. `evaluate` reads the pull request back and checks the stored manifest and text ([`verify`]).
//!
//! # Interfaces this stage needs from the others
//!
//! See [`input`] for the documents of the stages before it and for which commit is delivered.
//! [`DeliverySources`] and [`EvidenceDrift`] are for the composition root.
//!
//! # What this does not do
//!
//! * It cannot read the pull request body back: `ChangeHost` returns the tag of the body, not its
//!   text. The gate that the body carries the manifest hash reads the text this stage stored,
//!   and the body is written with the tag read from the host.
//! * It does not resolve a drift by itself. It tells the engine and stops.
//! * It takes the git tree id of the head from [`DeliverySources::tree_of`], because no port
//!   exposes it.

pub mod binding;
pub mod checks;
pub mod contract;
pub mod documentation_gate;
pub mod handler;
pub mod input;
pub mod manifest;
pub mod pr;
pub mod publish;
pub mod risk;
pub mod seams;
pub mod text;
mod verify;

pub use checks::{CHECK_REVIEW, CHECK_VALIDATION};
pub use contract::{GATES, MANIFEST, MANIFEST_GATE, PULL_REQUEST_GATE, RESULT};
pub use handler::{DeliveryConfig, DeliveryDeps, DeliveryHandler};
pub use seams::{
    CurrentValues, DeliverySources, DeliveryTarget, DocLink, EvidenceDrift, LedgerState, SeamError,
};
