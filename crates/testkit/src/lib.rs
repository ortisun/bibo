//! Labelled fakes for the tests of other crates, and the contract suites that keep them honest.
//! Every fake reports fidelity `fake`. This crate may appear only as a dev-dependency (rule
//! DEP-03, checked by `cargo xtask check-architecture`).
//!
//! # The two halves
//!
//! * **Fakes.** In-memory stand-ins for the ports of `factory-ports`. Each starts from the port's
//!   documented contract, not from what is convenient for a test. A production run refuses a
//!   fake through `factory_ports::require_permitted`, and the test `every_fake_reports_fake_fidelity`
//!   checks that every port with a `fidelity` method has a fake here that says `fake`.
//! * **Contract suites** ([`contracts`]). One per port. A suite drives the port through its public
//!   methods only, so the same suite runs against the fake now and against the real adapter
//!   (`factory-storage`, `factory-sandbox`, `factory-runtime`, `factory-github`, `factory-egress`)
//!   when it exists. A fake that is easier than the contract fails its own suite. The suite fails a
//!   *wrong* fake too: every fake can be built with deliberate defects, and the tests in
//!   `crates/testkit/tests/` require the suite to catch each one.
//!
//! # Map
//!
//! | Module | Fake | Contract suite |
//! |---|---|---|
//! | [`clock`] | `FakeClock` (FX-CLOCK), `SequentialIdGenerator`, `FakeCancel` | none: three small types with unit tests |
//! | [`store`] | `InMemoryStore` | `contracts::store` |
//! | [`artifact`] | `InMemoryArtifactStore` | `contracts::artifact` |
//! | [`sandbox`] | `FakeSandbox` | `contracts::sandbox` |
//! | [`workspace`] | `FakeWorkspaceProvider` | `contracts::workspace` |
//! | [`agent`] | `FakeAgentRuntime`, the scripted adversarial runtime (FX-ADV) | `contracts::agent` |
//! | [`broker`] | `FakeModelBroker` | `contracts::broker` |
//! | [`router`] | `StaticModelRouter` | `contracts::router` |
//! | [`registry`] | `InMemoryAgentRegistry` | `contracts::registry` |
//! | [`githost`] | `FakeChangeHost`, `FakeIssueSource` | `contracts::githost` |
//! | [`spec`] | `FakeSpecificationProvider` | none yet: Spec Kit is driven only by `spec_adapter` |
//! | [`fixtures`] | typed identifiers, a valid ledger entry and domain event, a sandbox policy and spec, an agent run request | |
//!
//! `OutputValidator` has no fake on purpose: the real validator is pure and fast, and tests use it
//! directly.
//!
//! # What the fakes do not do
//!
//! They start no process, container, database or network connection and run no git. They cannot
//! show that a real adapter handles a real daemon, a real clock skew or a real file system. A
//! contract check that a fake cannot support is reported as *skipped* by the real adapter's
//! subject, never as passed, and the adapter's own tests must cover it.

pub mod agent;
pub mod artifact;
pub mod broker;
pub mod clock;
pub mod contracts;
pub mod fixtures;
pub mod githost;
pub mod registry;
pub mod router;
pub mod sandbox;
pub mod spec;
pub mod store;
pub mod workspace;
