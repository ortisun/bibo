//! The shared composition core: what every binary of the factory is made of before it adds its own
//! shell.
//!
//! This is a ring 3 **library** (ADR 0015). The worker, and later the API and the operator CLI,
//! depend on it. It chooses adapters, reads the protected configuration, runs the start-up
//! checks and implements the seams that the stage handlers and the engine declare. It holds no
//! `main`, no HTTP routes, no handling of process arguments and no worker loop: those belong to the binary.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | [`commands`] | The pure parsers that turn a comment, command line arguments or a form into an approval command |
//! | [`config`] | The typed configuration: files and environment, secrets by file reference, defaults that fail closed |
//! | [`profile`] | `production`, `local`, `test`, and which port may be a fake in each |
//! | [`providers`] | The real Docker sandbox, host-side workspace and Spec Kit provider, assembled from the configuration |
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
//! | [`runtimes`] | One agent runtime that serves every tenant, finding the tenant of each call |
//! | [`seams`], [`authority`], [`sandbox_specs`] | The seams the stages declare |
//! | [`indexing`] | Indexes the artifacts a sandbox writes, for the tenant, when they are written |
//! | [`ledger`] | The task ledger of the implementation stage, over the store, fenced by attempt and epoch |
//! | [`hooks`] | The work a binary's loop does before it claims |
//! | [`pipeline`] | The whole pipeline from the configuration: the thirteen handlers, the engine, the approval service, the hook and the preflight, with the profile's check of every port (AUT-13) |
//! | [`preflight`] | The protection preflight recorder: a step before each claim that reads the protection of the default branch, judges it against the policy and records the result |
//! | [`assemble`] | Start-up in order, and the list of adapters that are not assembled |
//! | [`webhook`] | The webhook verifier of the API, built from secret files (one per secret in the rotation window) |
//! | [`supply_chain`] | The sources of the dependency gates that no adapter implements yet: blocked by design in production, labelled stand-ins in the other profiles |
//! | [`dependency_decisions`] | A person's decision on a new dependency or its build code: the request the API records, and the step that applies it through the engine |
//! | [`decision_signing`] | The keyed word that proves the API wrote a request for a decision, and the keys it is made and checked with (AUT-12) |
//!
//! Composition is the one job of this crate, so no module here contains a business rule. The
//! engine decides, the adapters act, and this crate chooses and connects them.

pub mod assemble;
pub mod authority;
pub mod commands;
pub mod config;
pub mod database;
pub mod decision_signing;
pub mod decisions;
pub mod delivery;
pub mod dependency_decisions;
pub mod drift;
pub mod feedback;
pub mod health;
pub mod hooks;
pub mod indexing;
pub mod intake_rejections;
pub mod ledger;
pub mod pipeline;
pub mod preflight;
pub mod profile;
pub mod providers;
pub mod reading;
pub mod redaction;
pub mod registry;
pub mod risk;
pub mod runtimes;
pub mod sandbox_specs;
pub mod seams;
pub mod specs;
pub mod startup;
pub mod supply_chain;
pub mod system;
pub mod telemetry;
pub mod webhook;
