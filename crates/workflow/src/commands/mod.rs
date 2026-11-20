//! What a person, an operator or the system can ask the engine to do, and who may ask.
//!
//! A command is a request. The engine checks who is asking, reads the state, evaluates the guard
//! and applies the move, or refuses with a typed error that leaves the state as it was. A command
//! carries an id, and the events it causes carry the same id as their causation, so a repeated
//! command is recognised and returns the first result (state-machine.md, ground rule 7).

mod authority;
mod decision;
mod dependency;

pub use authority::{Authority, AuthorityError};
pub use decision::{Actor, Decision, JobCommand, OverrideFacts, SoloRequest, Subject};
pub use dependency::{
    DependencyDecisionRecorded, ProjectBuildCodeRecorded, RecordDependencyDecision,
    RecordProjectBuildCodeDecision, RecordWarningDecision, WarningDecisionRecorded,
};
