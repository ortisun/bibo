//! The GitHub App adapter for the issue source and change host ports. It never merges.
//!
//! This crate implements [`factory_ports::githost::IssueSource`],
//! [`factory_ports::githost::ChangeHost`] and [`factory_ports::githost::WebhookVerifier`] for
//! GitHub, authenticated as a GitHub App (ports-v1.1, ADR 0014). It has no merge call, no call
//! that marks a pull request ready for review, and no call that writes a workflow file.
//!
//! # Dependencies (decision of work package `s1-github-adapter`, 2026-10-28)
//!
//! The crate needs an HTTP client, TLS for production, and RS256 signing for the App JWT. The
//! choice was made with `cargo info`, `cargo deny --locked check` (the unchanged `deny.toml`) and
//! `cargo audit --deny warnings`, on a scratch manifest holding each candidate set.
//!
//! | Candidate | Result |
//! |---|---|
//! | `rsa` (also what `jsonwebtoken` uses with its `rust_crypto` feature) | `cargo deny`: advisories FAILED, RUSTSEC-2023-0071 (Marvin attack, timing side channel). No fixed version. Rejected. The advisory is not ignored. |
//! | `jsonwebtoken` with `aws_lc_rs` | Passes deny, but adds a second crypto stack (`aws-lc-rs`, `aws-lc-sys`, `cmake` at build time) for work that is 60 lines with a signer. Rejected. |
//! | `openssl` command line through a process runner | DEP-10 allows only `docker` and `git` to be spawned, and the private key would have to be written to disk or piped. Rejected. |
//! | **`ring` 0.17.14 for RS256, `ureq` 3.5.0 (`rustls` feature only) for HTTP and TLS** | Passes deny (`advisories ok, bans ok, licenses ok, sources ok`) and audit. `ring` is also the crypto provider of `rustls`, so one crypto library does both jobs. About 25 new crates, no `unsafe` in this crate. **Chosen.** |
//!
//! `ring` and `ureq` and `async-trait` are not yet in the `github` `external_allow` list of
//! `docs/architecture/crate-dependency-rules.json`, so `cargo xtask check-architecture` reports
//! DEP-04 for them until the architect amends that file. That file is outside this package.
//!
//! The JWT signer is behind the [`JwtSigner`] trait. If the choice of `ring` is not approved, a
//! different signer (a signing service, a hardware module) replaces [`RingRs256Signer`] and
//! nothing else changes.
//!
//! # What is not verified
//!
//! Nothing here has run against the real GitHub: no App is registered. The tests run against the
//! fake GitHub server of the test kit (FX-GH) over the loopback interface, with keys made at run
//! time. See the "UNVERIFIED" notes on each module.

mod encoding;
mod jwt;
mod ureq_transport;
mod wire;

pub use encoding::{base64_decode, base64url_encode, percent_encode_component};
pub use jwt::{AppJwt, JwtError, JwtSigner, RingRs256Signer};
pub use ureq_transport::{MAX_RESPONSE_BYTES, REQUEST_TIMEOUT, UreqTransport};
pub use wire::{ApiBase, BadApiBase, Method, Transport, TransportError, WireRequest, WireResponse};
