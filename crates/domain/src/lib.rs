//! The domain model: identifiers, value objects, the Job, StageRun, Attempt and TaskNode state
//! machines, guards, contract types, and pure policy evaluation. Ring 0 of the workspace: it makes
//! no I/O, clock or random call and uses no async runtime.
//!
//! Time and identifiers come in as parameters: a [`Timestamp`](values::Timestamp) is built from a
//! value the `Clock` port produced or from a document, and an identifier is wrapped from a UUID
//! the `IdGenerator` port produced. Nothing here reads the environment or the file system.

mod macros;

pub mod error;
pub mod ids;
pub mod patterns;
pub mod scope;
pub mod values;
