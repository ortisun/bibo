//! Reference constructors for the six span kinds.
//!
//! Each function builds a `tracing` span with the name and the required attributes from
//! [`crate::names`], taking its parent from the current span. They show the exact shape the
//! conventions page asks for, and the tests use them as the oracle.
//!
//! Application and adapter crates cannot depend on this crate, so they write the same `tracing`
//! calls with the same literal names. The `s1-observability-instrumentation` package checks the
//! spans they produce against [`crate::names::check_span_shape`].
//!
//! Attributes that are only known when the work ends, `factory.outcome` and
//! `factory.error_class`, are declared empty and filled in with [`record_outcome`] and
//! [`record_error_class`].

use crate::names::{attr, span};
use tracing::{Span, field::Empty, info_span};

pub struct Job<'a> {
    pub correlation_id: &'a str,
    pub job_id: &'a str,
    pub tenant_id: &'a str,
}

pub struct StageRun<'a> {
    pub correlation_id: &'a str,
    pub job_id: &'a str,
    pub stage_run_id: &'a str,
    pub stage_kind: &'a str,
}

pub struct Attempt<'a> {
    pub correlation_id: &'a str,
    pub job_id: &'a str,
    pub stage_run_id: &'a str,
    pub attempt_id: &'a str,
    /// Recorded as `i64` on purpose. `tracing-opentelemetry` turns a `u64` field into a string.
    pub attempt_number: i64,
}

pub struct Agent<'a> {
    pub correlation_id: &'a str,
    pub job_id: &'a str,
    pub attempt_id: &'a str,
    pub agent_id: &'a str,
}

pub struct ToolCall<'a> {
    pub correlation_id: &'a str,
    pub job_id: &'a str,
    pub attempt_id: &'a str,
    pub tool_name: &'a str,
}

pub struct Gate<'a> {
    pub correlation_id: &'a str,
    pub job_id: &'a str,
    pub stage_run_id: &'a str,
    pub gate_id: &'a str,
}

pub fn job_span(f: &Job<'_>) -> Span {
    info_span!(
        span::JOB,
        { attr::CORRELATION_ID } = f.correlation_id,
        { attr::JOB_ID } = f.job_id,
        { attr::TENANT_ID } = f.tenant_id,
        { attr::OUTCOME } = Empty,
        { attr::ERROR_CLASS } = Empty,
    )
}

pub fn stage_run_span(f: &StageRun<'_>) -> Span {
    info_span!(
        span::STAGE_RUN,
        { attr::CORRELATION_ID } = f.correlation_id,
        { attr::JOB_ID } = f.job_id,
        { attr::STAGE_RUN_ID } = f.stage_run_id,
        { attr::STAGE_KIND } = f.stage_kind,
        { attr::OUTCOME } = Empty,
        { attr::ERROR_CLASS } = Empty,
    )
}

pub fn attempt_span(f: &Attempt<'_>) -> Span {
    info_span!(
        span::ATTEMPT,
        { attr::CORRELATION_ID } = f.correlation_id,
        { attr::JOB_ID } = f.job_id,
        { attr::STAGE_RUN_ID } = f.stage_run_id,
        { attr::ATTEMPT_ID } = f.attempt_id,
        { attr::ATTEMPT_NUMBER } = f.attempt_number,
        { attr::OUTCOME } = Empty,
        { attr::ERROR_CLASS } = Empty,
    )
}

pub fn agent_span(f: &Agent<'_>) -> Span {
    info_span!(
        span::AGENT,
        { attr::CORRELATION_ID } = f.correlation_id,
        { attr::JOB_ID } = f.job_id,
        { attr::ATTEMPT_ID } = f.attempt_id,
        { attr::AGENT_ID } = f.agent_id,
        { attr::OUTCOME } = Empty,
        { attr::ERROR_CLASS } = Empty,
    )
}

pub fn tool_call_span(f: &ToolCall<'_>) -> Span {
    info_span!(
        span::TOOL_CALL,
        { attr::CORRELATION_ID } = f.correlation_id,
        { attr::JOB_ID } = f.job_id,
        { attr::ATTEMPT_ID } = f.attempt_id,
        { attr::TOOL_NAME } = f.tool_name,
        { attr::OUTCOME } = Empty,
        { attr::ERROR_CLASS } = Empty,
    )
}

pub fn gate_span(f: &Gate<'_>) -> Span {
    info_span!(
        span::GATE,
        { attr::CORRELATION_ID } = f.correlation_id,
        { attr::JOB_ID } = f.job_id,
        { attr::STAGE_RUN_ID } = f.stage_run_id,
        { attr::GATE_ID } = f.gate_id,
        { attr::OUTCOME } = Empty,
        { attr::ERROR_CLASS } = Empty,
    )
}

/// Record how the work ended. Call it once, just before the span closes.
pub fn record_outcome(span: &Span, outcome: &str) {
    span.record(attr::OUTCOME, outcome);
}

/// Record the failure class when the work failed.
pub fn record_error_class(span: &Span, class: &str) {
    span.record(attr::ERROR_CLASS, class);
}
