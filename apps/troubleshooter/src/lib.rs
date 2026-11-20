//! The troubleshooter (ADR 0021): watches the factory itself and files issues for a person.
//!
//! This library is what `apps/troubleshooter` is made of; `src/main.rs` is a thin shell around it.
//! The shared wiring (configuration sections, policies, redactor, broker, sandbox specs, GitHub
//! adapter, telemetry) is the composition library's (ADR 0015). What is here is the
//! troubleshooter's own:
//!
//! | Module | What it holds |
//! |---|---|
//! | [`config`] | The configuration file: gateway, store, observer login, broker, sandbox, GitHub, API health URL |
//! | [`boot`] | Start-up: the checks that refuse a bad deployment, then the real parts |
//! | [`scheduler`] | One active troubleshooter (an advisory lock), and the probe period loop |
//! | [`troubleshooter`] | One pass: probes, an agent run when due, issue decisions, the run record |
//! | [`probes`] | What each probe kind calls and how its answer is read |
//! | [`exact`] | Exact decimal comparison of an observed value with a threshold |
//! | [`schedule`] | The policy's period, sweep, cool-down and daily caps as pure functions |
//! | [`findings`] | The report's schema and evidence checks, the fingerprint input, `source_unavailable` findings |
//! | [`agent`] | The agent run seam and the real run in the troubleshooter sandbox |

pub mod agent;
pub mod boot;
pub mod config;
pub mod exact;
pub mod findings;
pub mod probes;
pub mod schedule;
pub mod scheduler;
pub mod troubleshooter;
