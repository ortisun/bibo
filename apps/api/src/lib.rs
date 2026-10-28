//! The HTTP API: a composition root in ring 3 (ADR 0002).
//!
//! It receives GitHub webhooks, accepts jobs and decisions from people, and answers status and
//! timeline queries. It chooses its adapters through the composition library (ADR 0015), depends on
//! the `WebhookVerifier` port and not on the `github` crate (ADR 0014), and connects to the
//! database as the **API login only** (ADR 0012): a member of `factory_app` and `factory_resolver`,
//! with no system pool, so it cannot find work across tenants and cannot do what the engine login
//! does.
//!
//! | Module | What it holds |
//! |---|---|
//! | [`config`] | The typed configuration of the API |
//! | [`boot`] | Start-up in order: policy, redactor, telemetry, the API pool, the webhook verifier, the ports check |
//! | [`state`] | The ports the handlers use, and the profile check over them |
//! | [`tokens`] | The shape of an API token and its hash |
//! | [`auth`] | Token authentication and the roles of the caller |
//! | [`answers`] | Every answer the API gives, with a closed set of error codes |
//! | [`limits`] | Fixed-window rate limits and the bounded queue of platform audit events |
//! | [`routes`] | The route table, the router and the request pipeline |
//! | [`jobs`], [`decisions`], [`webhook`], [`health`] | The handlers |
//! | [`server`] | The connection loop: header timeout, connection limit, graceful shutdown |
//! | [`openapi`] | The OpenAPI document, served and checked against the route table |
//!
//! # Rules every handler keeps
//!
//! * A body is read only after the checks that need no body, with a hard size limit and a time
//!   limit. A webhook body is verified on its raw bytes before anything parses it.
//! * An error answer carries a code from a closed set and nothing else: no stack trace, no SQL, no
//!   library message, nothing the caller sent.
//! * Authority comes from the numeric GitHub id of the principal behind the token, mapped to the
//!   protected allowlist. A login string is never read for a decision.
//! * The address of the peer is the TCP peer. `X-Forwarded-*` headers are never read.
//! * A token, a secret or a body is never logged.

pub mod answers;
pub mod auth;
pub mod boot;
pub mod config;
pub mod decisions;
pub mod health;
pub mod jobs;
pub mod limits;
pub mod openapi;
pub mod routes;
pub mod server;
pub mod state;
pub mod tokens;
pub mod webhook;
