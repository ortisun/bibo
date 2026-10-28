//! The model broker and the per-job egress relay. The broker holds the provider keys; the relay
//! and the agents inside the sandbox hold none.
//!
//! # Map
//!
//! | Module | What it is |
//! |---|---|
//! | [`broker`] | The pure broker: job tokens (random, hashed at rest, bound to a job and a provider, expiring, revocable), the price list, the caps, the per-job ledger and the audit events. Implements `ModelBroker` and `MeteringOps`. |
//!
//! The `broker` feature (on by default) holds everything that knows about tokens, providers and
//! money. The sidecar binary builds this crate without it.
//!
//! # Not verified
//!
//! Nothing here has met a real provider. Every test runs against a labelled fake provider with
//! keys made at run time. The live smoke test reports `BLOCKED` until a person supplies one
//! Anthropic and one OpenAI key with a provider-side spend limit.

#[cfg(feature = "broker")]
pub mod broker;
#[cfg(feature = "broker")]
pub mod http;
