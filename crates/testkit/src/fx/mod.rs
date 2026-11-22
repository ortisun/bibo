//! The security test harness (work package `s1-security-test-harness`).
//!
//! These are the fixtures of the negative-test catalog (`docs/security/negative-test-catalog.md`,
//! section 2). They let the packages that build the sandbox, the egress relay, the GitHub adapter
//! and the workspace ingestion test their controls against an attacker, without a real GitHub,
//! registry, DNS or provider, and without letting hostile content run on the host.
//!
//! # The components
//!
//! | Catalog ID | Module | What it is |
//! |---|---|---|
//! | FX-CANARY | [`canary`] | Fake secrets in real formats, made at run time, and a sweeper that finds them raw, in base64, base64url, hex, percent-encoded and JSON-escaped forms, across chunk boundaries and through colour codes |
//! | FX-SINKS | [`sinks`] | One collector for everything a job can leak into (streams, telemetry attributes, audit and outbox rows, artifacts, prompts, GitHub requests, environments, process arguments) |
//! | FX-GH | [`github`] | A fake GitHub: REST subset, App tokens narrowed per repository and permission, signed webhooks with forged variants, a reference verifier and receiver |
//! | FX-SPAWN | [`spawn`] | Records the programs the code under test starts, with their arguments and environment, and traps shells (unix only) |
//! | FX-DOCKER | [`docker`] | BLOCKED when there is no daemon, and cleanup of everything a test run labelled |
//! | FX-DNS | [`dns`] | A DNS server that flips answers, a connection-noting listener, a scripted HTTP server |
//! | FX-REG | [`registry`] | A fake crates and npm registry with real tarballs, controllable age, install scripts and lookalike names |
//! | FX-AUTH | [`auth`] | The authority allowlist, and a reference decision that cannot see a GitHub role |
//! | FX-REPO-CLEAN, FX-REPO-HOSTILE | [`repos`] | The fixture repositories (data in `fixtures/repos/security/`), a writer, and a planter for the entries git cannot store |
//!
//! Supporting pieces: [`encoding`] and [`digest`] (hand-written, because the testkit may use only
//! three external crates), [`rng`], [`timeutil`], [`tmpdir`], [`http`] (a loopback HTTP server and
//! client), [`archive`] (tar and gzip writers, including hostile entries) and [`control`], the
//! control-off check that every test of the catalog must pass.
//!
//! Not built here: FX-EXEC (it needs the sandbox adapter's containers) and FX-ADV-P (it needs the
//! agent-runtime spike). FX-CLOCK and FX-ADV are in the testkit already.
//!
//! # Rules every component follows
//!
//! * **Labelled fake.** Records say `"fidelity": "fake"`, servers add `X-Factory-Fidelity: fake`
//!   to each response, and generated secrets carry the marker `CANARY`.
//! * **Loopback only.** Servers bind `127.0.0.1` and nothing else. Nothing reaches a real host.
//! * **No secret stored.** Canaries are made when a test runs, and a stored fixture holds only a
//!   placeholder.
//! * **Nothing hostile runs on the host.** Hostile fixtures are text that is written to disk. The
//!   one test that runs a piece of one starts it in a container with the hardened profile.
//! * **BLOCKED is not PASSED.** A test that needs Docker, or an image, panics with a message that
//!   starts `BLOCKED:`. There is no skip.
//! * **Every control can fail.** Each module's tests include a deliberate break, and
//!   [`control`] checks a scenario both ways.
//!
//! # Blocking
//!
//! The servers and recorders here use blocking sockets and threads, not `tokio`. An async test
//! can use them directly: they bind a port and return, and a client in the code under test
//! connects as it would to any server.

pub mod archive;
pub mod auth;
pub mod canary;
pub mod control;
pub mod digest;
pub mod dns;
pub mod docker;
pub mod encoding;
pub mod github;
pub mod http;
pub mod registry;
pub mod repos;
pub mod rng;
pub mod scratch;
#[cfg(test)]
mod self_check;
pub mod sinks;
#[cfg(unix)]
pub mod spawn;
pub mod timeutil;
pub mod tmpdir;
