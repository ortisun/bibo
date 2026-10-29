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
use factory_domain::ids::JobId;
use factory_domain::values::Traceparent;
use opentelemetry::Context;
use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState};
use tracing::{Span, field::Empty, info_span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

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

/// One stretch of work on a job: the API while it handles a command, the worker while it holds a
/// claim.
pub struct JobStretch<'a> {
    pub correlation_id: &'a str,
    /// The job. Its identifier decides the trace, so the type is the job id and not a string.
    pub job: JobId,
    pub tenant_id: &'a str,
}

/// The remote parent of every `factory.job` span of a job (ADR 0013, decision 3).
///
/// A job lives for hours or days, across restarts and across the API and the worker, and a span
/// is exported only when it ends, so no span can last for the whole job. Instead the job has a
/// trace context that any process computes from the job id with
/// [`Traceparent::for_job`](factory_domain::values::Traceparent::for_job): the trace id is the
/// job's UUID, the span id is derived from the job id, and the flags say sampled. The context is
/// remote because the span it names is never exported. Backends show each stretch as a child of a
/// missing parent inside one trace.
#[must_use]
pub fn job_trace_context(job: JobId) -> SpanContext {
    let derived = Traceparent::for_job(job);
    let mut parts = derived.as_str().split('-').skip(1);
    // The domain function writes `00-<32 hex>-<16 hex>-01`, so both parses succeed. If they ever
    // fail, an invalid context makes the stretch a root span, and the test of the derived trace
    // id fails.
    let trace_id = parts
        .next()
        .and_then(|hex| TraceId::from_hex(hex).ok())
        .unwrap_or(TraceId::INVALID);
    let span_id = parts
        .next()
        .and_then(|hex| SpanId::from_hex(hex).ok())
        .unwrap_or(SpanId::INVALID);
    SpanContext::new(
        trace_id,
        span_id,
        TraceFlags::SAMPLED,
        true,
        TraceState::default(),
    )
}

/// The `factory.job` span of one stretch of work, parented to the job's derived trace context.
///
/// Run the engine call inside it: `stage run`, `attempt`, `agent`, `tool call` and `gate` spans
/// created below it take it as their parent and join the job's trace. Two processes that work on
/// one job, one after the other or at the same time, write into one trace, and a restart needs no
/// stored state.
///
/// Without an OpenTelemetry layer on the subscriber (no collector is configured), the span is a
/// plain `tracing` span and nothing is exported, so setting the parent is skipped silently.
pub fn job_stretch_span(f: &JobStretch<'_>) -> Span {
    let stretch = info_span!(
        span::JOB,
        { attr::CORRELATION_ID } = f.correlation_id,
        { attr::JOB_ID } = f.job.to_string(),
        { attr::TENANT_ID } = f.tenant_id,
        { attr::OUTCOME } = Empty,
        { attr::ERROR_CLASS } = Empty,
    );
    let parent = Context::new().with_remote_span_context(job_trace_context(f.job));
    // Fails when there is no OpenTelemetry layer, or the span is filtered out. Either way there is
    // nothing to join. `AlreadyStarted` cannot happen: the span has not been entered yet.
    let _ = stretch.set_parent(parent);
    stretch
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
