//! The review stage tests.

use std::sync::Arc;

use factory_workflow::handlers::HandlerRegistry;

use crate::rig::{RigRework, RigSpecs, StandInCheck};

/// Registers the real review handler.
pub fn register(
    _handlers: &mut HandlerRegistry,
    _check: &Arc<StandInCheck>,
    _specs: &Arc<RigSpecs>,
    _rework: &Arc<RigRework>,
) {
    unimplemented!("the review handler is registered in the next increment")
}
