//! The shared composition core: what every binary of the factory is made of before it adds its own
//! shell.
//!
//! This is a ring 3 **library** (ADR 0015). The worker, and later the API and the operator CLI,
//! depend on it. It chooses adapters, reads the protected configuration, runs the start-up
//! checks and implements the seams that the stage handlers and the engine declare. It holds no
//! `main`, no HTTP routes, no command parser and no worker loop: those belong to the binary.
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
//! | [`database`] | The two pools and the two logins (ADR 0012) |
//! | [`delivery`] | `ApprovalSources` and `DeliverySources` over the store (two delivery methods are BLOCKED, see the module) |
//! | [`drift`] | The evidence-drift seam: a channel from the stage handlers to the thread that owns the engine |
//! | [`feedback`] | `ReworkSource` and `RoundSource`: why a run replaces another, read from the evidence the engine stored |
//! | [`risk`] | `RiskSource`: the agent's risk claim from the stored intake, and the facts of the domain profile |
//! | [`reading`] | Shared reads of stage run outputs, the ledger and the artifact store |
//! | [`specs`] | The specification stage's `SpecDrafts`, `SpecApprovals` and `SpecHistory` over the store |
//! | [`health`] | Health and readiness as plain data |
//! | [`telemetry`] | The telemetry configuration with the real scrubber, and the `factory.job` stretch span |
//! | [`system`] | The real clock, identifier source, `Ticker` and the shutdown signal |
//! | [`seams`], [`authority`], [`sandbox_specs`] | The seams the stages declare |
//! | [`indexing`] | Indexes the artifacts a sandbox writes, for the tenant, when they are written |
//! | [`ledger`] | The task ledger of the implementation stage, over the store, fenced by attempt and epoch |
//! | [`hooks`] | The work a binary's loop does before it claims |
//! | [`assemble`] | Start-up in order, and the list of adapters that are not assembled |
//!
//! Composition is the one job of this crate, so no module here contains a business rule. The
//! engine decides, the adapters act, and this crate chooses and connects them.

pub mod assemble;
pub mod authority;
pub mod config;
pub mod database;
pub mod delivery;
pub mod drift;
pub mod feedback;
pub mod health;
pub mod hooks;
pub mod indexing;
pub mod ledger;
pub mod profile;
pub mod reading;
pub mod redaction;
pub mod registry;
pub mod risk;
pub mod sandbox_specs;
pub mod seams;
pub mod specs;
pub mod startup;
pub mod system;
pub mod telemetry;
