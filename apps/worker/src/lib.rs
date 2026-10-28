//! The shared composition core and the worker's parts.
//!
//! This library is what `apps/worker` is made of. `src/main.rs` is a thin shell around it. The
//! API and the operator CLI are later parts of the same work package and will reuse the core
//! modules (everything except [`run`]).
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | [`config`] | The typed configuration: files and environment, secrets by file reference, defaults that fail closed |
//! | [`profile`] | `production`, `local`, `test`, and which port may be a fake in each |
//! | [`registry`] | The registry of ports and the check that a profile accepts every one |
//! | [`startup`] | Start-up checks that need no database: the policy from the protected checkout, hashed, and the image catalog |
//! | [`redaction`] | The redactor built from the policy, the registry of the factory's secret values, the telemetry scrubber and the broker wrapper that registers job tokens |
//! | [`health`] | Health and readiness as plain data |
//! | [`telemetry`] | The telemetry configuration with the real scrubber, and the `factory.job` stretch span |
//! | [`system`] | The real clock, identifier source, `Ticker` and the shutdown signal |
//! | [`run`] | The worker loop |
//!
//! Composition is the one job of this package, so no module here contains a business rule. The
//! engine decides, the adapters act, and this package chooses and connects them.

pub mod authority;
pub mod config;
pub mod database;
pub mod health;
pub mod profile;
pub mod redaction;
pub mod registry;
pub mod run;
pub mod sandbox_specs;
pub mod seams;
pub mod startup;
pub mod system;
pub mod telemetry;
