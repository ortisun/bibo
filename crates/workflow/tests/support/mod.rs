//! Shared test harness: a whole engine over the in-memory fakes with scripted stage handlers.
//!
//! Each test file includes it with `mod support;` and uses the parts it needs, so an item that
//! one file does not use is not a warning.
#![allow(dead_code, unused_imports)]

pub mod artifacts;
pub mod authority;
pub mod backend;
pub mod handler;
pub mod ids;
pub mod ticker;
pub mod world;

pub use authority::StaticAuthority;
pub use backend::{Backend, InMemoryBackend};
pub use handler::{Eval, ScriptHandle, ScriptedHandler, Step, Tweaks};
pub use ticker::ManualTicker;
#[allow(unused_imports)]
pub use world::{REQUESTER_GITHUB_ID, ScriptedValidator, World, solo_policy, solo_proof};
