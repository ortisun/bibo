//! The worker: the engine loop and the model broker listener, on top of the shared composition
//! core.
//!
//! This library is what `apps/worker` is made of. `src/main.rs` is a thin shell around it. The
//! configuration, the profiles, the registry of ports, the start-up checks, the redactor, the
//! seams and the health report are in the `factory-composition` library crate (ADR 0015), which
//! the API and the operator CLI reuse. What stays here is specific to a process that claims work:
//!
//! | Module | What it holds |
//! |---|---|
//! | [`boot`] | Start-up of the worker: the shared checks, then the broker listener, then the secret-kind check |
//! | [`broker_host`] | Hosts the model broker listener in the worker's process |
//! | [`run`] | The worker loop |
//!
//! No module here contains a business rule. The engine decides, the adapters act, and the
//! composition crate chooses and connects them.

pub mod boot;
pub mod broker_host;
pub mod run;
