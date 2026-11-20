//! The set of stage handlers an engine runs: one per stage kind.

use std::collections::BTreeMap;
use std::sync::Arc;

use factory_domain::vocabulary::StageKind;

use super::StageHandler;
use crate::engine::config::position;

/// Why a handler could not be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// A handler for this stage kind is already registered.
    #[error("a handler for the {0} stage is already registered")]
    Duplicate(StageKind),
}

/// The handlers of one engine, by stage kind.
#[derive(Clone, Default)]
pub struct HandlerRegistry {
    handlers: BTreeMap<usize, Arc<dyn StageHandler>>,
}

impl std::fmt::Debug for HandlerRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.kinds()).finish()
    }
}

impl HandlerRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a handler for the stage kind it reports.
    ///
    /// # Errors
    /// [`RegistryError::Duplicate`] when a handler for that kind is already registered.
    pub fn register(&mut self, handler: Arc<dyn StageHandler>) -> Result<(), RegistryError> {
        let kind = handler.kind();
        let key = position(kind);
        if self.handlers.contains_key(&key) {
            return Err(RegistryError::Duplicate(kind));
        }
        self.handlers.insert(key, handler);
        Ok(())
    }

    /// The handler for a stage kind.
    #[must_use]
    pub fn get(&self, kind: StageKind) -> Option<&Arc<dyn StageHandler>> {
        self.handlers.get(&position(kind))
    }

    /// The stage kinds that have a handler, in pipeline order.
    #[must_use]
    pub fn kinds(&self) -> Vec<StageKind> {
        self.handlers
            .values()
            .map(|handler| handler.kind())
            .collect()
    }

    /// Every handler, in pipeline order.
    pub fn all(&self) -> impl Iterator<Item = &Arc<dyn StageHandler>> {
        self.handlers.values()
    }
}
