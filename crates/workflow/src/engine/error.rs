//! Why an engine call failed. The set is closed, like the error sets of the ports.
//!
//! A variant carries plain data. It never holds a prompt, issue text, agent output or a secret, so
//! an error can be logged and returned to a caller as it is.

use factory_domain::error::ValueError;
use factory_domain::machines::guards::GuardFailure;
use factory_domain::state::IllegalTransition;
use factory_domain::vocabulary::StageKind;
use factory_ports::FakeRefused;
use factory_ports::store::StoreError;

/// Why an engine call did not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    /// A fake adapter was offered to a production run (invariant INV-08).
    #[error(transparent)]
    FakeRefused(#[from] FakeRefused),
    /// The configuration cannot be used. The text says which rule it breaks.
    #[error("the engine configuration is not usable: {0}")]
    Config(&'static str),
    /// The state machine has no such move. Nothing was changed (invariant INV-02).
    #[error(transparent)]
    Illegal(#[from] IllegalTransition),
    /// The move exists and its guard does not hold. Nothing was changed.
    #[error(transparent)]
    GuardUnmet(#[from] GuardFailure),
    /// The row changed while the engine was deciding. Read again and retry.
    #[error("the state changed while the engine was deciding; read it again and retry")]
    Conflict,
    /// The write carries a lease epoch that is not current: the worker no longer holds the lease
    /// (invariant INV-05).
    #[error("the lease epoch is not current: this worker no longer holds the lease")]
    LeaseFenced,
    /// No such job, stage run or attempt for this scope. A row of another tenant looks the same.
    #[error("no such job, stage run or attempt for this scope")]
    NotFound,
    /// The principal may not do this. The text names the rule and never repeats a name from the
    /// allowlist.
    #[error("the principal is not allowed to do this: {0}")]
    NotAuthorized(&'static str),
    /// The command repeats one that was already applied. The first result stands.
    #[error("this command was already applied")]
    Duplicate,
    /// No handler is registered for the stage.
    #[error("no stage handler is registered for the {0} stage")]
    NoHandler(StageKind),
    /// The command is not valid in the state the aggregate is in, for a reason that is not a
    /// guard. The text says what.
    #[error("the command cannot be applied now: {0}")]
    Refused(&'static str),
    /// A fact the engine stored earlier could not be read back. The record is damaged or was
    /// written by something else.
    #[error("a stored engine fact is malformed: {0}")]
    Corrupt(&'static str),
    /// The engine built a value that the domain refuses. This is a bug in the engine.
    #[error("the engine built an invalid value: {0}")]
    Invalid(String),
    /// The artifact store failed. The text names the operation and never holds artifact content.
    #[error("the artifact store failed: {0}")]
    Artifacts(String),
    /// The store failed in a way the engine cannot repair.
    #[error("the store failed: {0}")]
    Store(StoreError),
}

impl From<StoreError> for EngineError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Conflict => Self::Conflict,
            StoreError::LeaseFenced => Self::LeaseFenced,
            StoreError::NotFound => Self::NotFound,
            other => Self::Store(other),
        }
    }
}

impl From<ValueError> for EngineError {
    fn from(error: ValueError) -> Self {
        Self::Invalid(error.to_string())
    }
}

impl EngineError {
    /// True when the call can be repeated after reading the state again: another writer got
    /// there first, or the store was briefly unavailable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Conflict | Self::Store(StoreError::Unavailable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_errors_map_onto_the_engine_set() {
        assert_eq!(
            EngineError::from(StoreError::Conflict),
            EngineError::Conflict
        );
        assert_eq!(
            EngineError::from(StoreError::LeaseFenced),
            EngineError::LeaseFenced
        );
        assert_eq!(
            EngineError::from(StoreError::NotFound),
            EngineError::NotFound
        );
        assert_eq!(
            EngineError::from(StoreError::Unavailable),
            EngineError::Store(StoreError::Unavailable)
        );
    }

    #[test]
    fn only_a_lost_race_or_a_brief_outage_is_worth_repeating() {
        assert!(EngineError::Conflict.is_retryable());
        assert!(EngineError::Store(StoreError::Unavailable).is_retryable());
        assert!(!EngineError::LeaseFenced.is_retryable());
        assert!(!EngineError::NotFound.is_retryable());
        assert!(!EngineError::Duplicate.is_retryable());
    }
}
