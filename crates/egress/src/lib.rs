//! The model broker and the per-job egress relay. The broker holds the provider keys; the relay
//! and the agents inside the sandbox hold none.
//!
//! # Map
//!
//! | Module | What it is |
//! |---|---|
//! | [`broker`] | The pure broker: job tokens (random, hashed at rest, bound to a job and a provider, expiring, revocable), the price list, the caps, the per-job ledger and the audit events. Implements `ModelBroker` and `MeteringOps`. |
//! | [`http`] | The broker's network side: the listener the sidecar forwards to, the call to the provider with the real key, streamed usage, the header allowlists and the key scrubber. |
//! | [`broker::shape`] | What may be in a request to a provider: a default-deny schema per API, strict JSON, the beta header and query allowlists, and the closed set of answer headers. The module documentation lists the allowed fields and why. |
//! | [`relay`] | The logic of the `factory-egress-sidecar` program: broker mode (the `agent` profile) and connect mode (the `fetch_deps` profile). |
//!
//! The `broker` feature (on by default) holds `broker` and `http`. The sidecar binary builds this
//! crate without it, so its image carries no code that knows about a token, a price or a key.
//!
//! # What the tests prove, and where
//!
//! | Claim | Test |
//! |---|---|
//! | The real broker keeps the `ModelBroker` contract, through the port and through the listener | `tests/broker_contract.rs`, `tests/http_contract.rs` |
//! | Revoking a job revokes every token of it; spend that reaches the ceiling revokes in the same step | `revoke_for_job_and_metering_*` in the two files above |
//! | A ceiling stops a looping client; recorded cost is at most the ceiling plus one request; audit events at 80 and 100 percent | `negative_nt_bud_01_*` |
//! | A tool that ignores its own budget is stopped, the refusal comes within two seconds, and the broker's count is the provider's | `negative_nt_bud_07_*` |
//! | The relay refuses lookalikes, userinfo, IP literals, internal addresses after resolution and rebinding, and stops at the byte quota | `negative_nt_sbx_05_*`, `relay_broker_mode.rs` |
//! | The real key is in no response, no log and no debug output | `real_key_never_leaves_the_broker` |
//! | No provider-side tool, remote server or fetched content crosses the broker; the requests of the real tools do | `negative_nt_sbx_17.rs`, `security_review` (`egr_1_*`) |
//! | The real tools, in the real container profile, reach the fake provider only through sidecar and broker | `tests/e2e_docker.rs` (BLOCKED without Docker or the images) |
//! | Each deliberate break is caught | `tests/mutations.py` |
//!
//! # Dependencies (decision of work package `s1-egress-and-broker`, 2026-10-28)
//!
//! The broker needs an HTTP/1.1 listener, a client with TLS to call the providers, a random source
//! and a hash for the job token. The choice follows the GitHub adapter's: blocking code on the
//! standard library and `ureq`, one thread per connection, no async runtime in production code.
//!
//! | Need | Chosen | Evidence | Not chosen |
//! |---|---|---|---|
//! | Provider client with TLS | `ureq` 3.5.0, feature `rustls` only | Already in `Cargo.lock` for `factory-github`; same release and features; supports a streamed body read, no redirects (`max_redirects(0)`), no proxy, per-phase timeouts | `reqwest` (pulls `hyper`, an async runtime and a second TLS configuration) |
//! | Request head parser | `httparse` 1.10.1 (`MIT OR Apache-2.0`, no dependencies) | Already in `Cargo.lock` through `ureq-proto` and `hyper`; the parser used by `hyper`; the code around it is about 150 lines and rejects chunked bodies, repeated lengths and odd targets | `hyper` or `axum` for the server (async, streaming bodies through two runtimes, a larger graph); a hand-written parser (request smuggling is the usual bug) |
//! | Random source and SHA-256 | `ring` 0.17.14 (`Apache-2.0 AND ISC`) | Already the crypto provider of `ureq`'s TLS and used by `factory-github`; `SystemRandom` and `digest::SHA256` mean no second crypto crate and no `sha2` or `getrandom` of our own | `sha2` (one more direct dependency for the same job) |
//!
//! The sidecar's own dependency graph is `serde_json` and `thiserror` and what they pull in (ten
//! crates, built in the pinned verify image). `cargo deny --locked check` and `cargo audit
//! --deny warnings` pass with the unchanged `deny.toml`. `httparse`, `ring` and `ureq` are not in
//! the `egress` entry of `docs/architecture/crate-dependency-rules.json` yet, so
//! `cargo xtask check-architecture` reports DEP-04 for exactly those three until the architect
//! adds them; with the three added in a scratch copy of the file, the check passes. A new direct
//! dependency needs a person (`policies/security.yaml`, `supply_chain.new_direct_dependency`).
//!
//! # Not verified
//!
//! Nothing here has met a real provider. Every test runs against a labelled fake provider with
//! keys made at run time. Streamed usage was read from the recorded shapes of the fake provider
//! and from the providers' published formats, not from real traffic. The live smoke test
//! (`tests/live_smoke.rs`) reports `BLOCKED` until a person supplies one Anthropic and one OpenAI
//! key with a provider-side spend limit. Nothing was run on Linux hardware; the end-to-end tests
//! ran on Docker Desktop for macOS (linux/arm64 containers).

#[cfg(feature = "broker")]
pub mod broker;
#[cfg(feature = "broker")]
pub mod http;
pub mod relay;
