//! A job is one trace, found from its id (ADR 0013, decision 3).
//!
//! Each process that works on a job opens a `factory.job` span for its stretch of work. The remote
//! parent of that span is the context derived from the job id, so two processes that never talk to
//! each other still write into one trace. The tests run two separate pipelines, with separate
//! exporters, as two processes would, and compare what each exported.

mod common;

use factory_domain::ids::JobId;
use factory_domain::values::Traceparent;
use factory_observability::names::{attr, span};
use factory_observability::spans::{
    self, JobStretch, StageRun, job_stretch_span, job_trace_context,
};
use factory_observability::telemetry::{
    Pipeline, TelemetryConfig, build_pipeline_with_span_exporter,
};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SpanData};

const CORRELATION: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77";
const TENANT: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a79";

fn job(text: &str) -> JobId {
    JobId::parse(text).expect("a job id")
}

fn process() -> (Pipeline, InMemorySpanExporter) {
    let config = TelemetryConfig::new("factory-test", "0.0.0", common::policy_scrubber());
    let exporter = InMemorySpanExporter::default();
    let pipeline =
        build_pipeline_with_span_exporter(&config, common::Capture::default(), exporter.clone())
            .expect("the pipeline builds");
    (pipeline, exporter)
}

fn exported(pipeline: &Pipeline, exporter: &InMemorySpanExporter) -> Vec<SpanData> {
    pipeline.flush().expect("flush");
    exporter.get_finished_spans().expect("read spans")
}

fn by_name<'a>(spans: &'a [SpanData], name: &str) -> &'a SpanData {
    spans
        .iter()
        .find(|s| s.name.as_ref() == name)
        .unwrap_or_else(|| panic!("no span named {name} in {spans:?}"))
}

/// One stretch of work: the stretch span with a stage run inside it, as the worker does for one
/// attempt.
fn work_on(job_id: JobId, pipeline: &Pipeline) {
    pipeline.in_scope(|| {
        let stretch = job_stretch_span(&JobStretch {
            correlation_id: CORRELATION,
            job: job_id,
            tenant_id: TENANT,
        });
        let _in_stretch = stretch.enter();
        let stage_run = spans::stage_run_span(&StageRun {
            correlation_id: CORRELATION,
            job_id: &job_id.to_string(),
            stage_run_id: "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a80",
            stage_kind: "INTAKE",
        });
        drop(stage_run.enter());
    });
}

#[test]
fn job_stretch_uses_the_derived_trace_id() {
    let id = job("0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78");
    let (pipeline, exporter) = process();
    work_on(id, &pipeline);
    let spans = exported(&pipeline, &exporter);

    let derived = Traceparent::for_job(id);
    let wanted_trace = derived
        .as_str()
        .split('-')
        .nth(1)
        .expect("trace id")
        .to_string();
    let wanted_parent = derived
        .as_str()
        .split('-')
        .nth(2)
        .expect("span id")
        .to_string();
    assert_eq!(spans.len(), 2, "{spans:?}");

    let stretch = by_name(&spans, span::JOB);
    assert_eq!(
        stretch.span_context.trace_id().to_string(),
        wanted_trace,
        "the stretch is not in the job's trace"
    );
    assert_eq!(stretch.parent_span_id.to_string(), wanted_parent);
    assert!(
        stretch.parent_span_is_remote,
        "the derived parent was never exported, so it is remote"
    );

    let stage_run = by_name(&spans, span::STAGE_RUN);
    assert_eq!(
        stage_run.span_context.trace_id().to_string(),
        wanted_trace,
        "work inside the stretch stays in the trace"
    );
    assert_eq!(
        stage_run.parent_span_id,
        stretch.span_context.span_id(),
        "the stage run hangs from the stretch"
    );
}

#[test]
fn the_trace_id_is_the_job_uuid_without_hyphens() {
    let id = job("0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78");
    let context = job_trace_context(id);
    assert_eq!(
        context.trace_id().to_string(),
        "0192f3a47b1c7d3e9a521c8f0e4b6a78"
    );
    assert!(context.is_remote());
    assert!(context.is_sampled(), "the flags are 01");
    assert!(context.is_valid());
}

#[test]
fn two_processes_on_one_job_write_one_trace_with_the_same_parent() {
    let id = job("0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78");
    let (first_process, first_exporter) = process();
    let (second_process, second_exporter) = process();
    work_on(id, &first_process);
    // The first process ends, and a second one picks the job up later.
    drop(first_process.flush());
    work_on(id, &second_process);

    let first = exported(&first_process, &first_exporter);
    let second = exported(&second_process, &second_exporter);
    let (a, b) = (by_name(&first, span::JOB), by_name(&second, span::JOB));
    assert_eq!(a.span_context.trace_id(), b.span_context.trace_id());
    assert_eq!(
        a.parent_span_id, b.parent_span_id,
        "a restart changed the remote parent"
    );
    assert_ne!(
        a.span_context.span_id(),
        b.span_context.span_id(),
        "each stretch is its own span"
    );
}

#[test]
fn another_job_is_another_trace() {
    let (pipeline, exporter) = process();
    work_on(job("0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78"), &pipeline);
    work_on(job("0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a99"), &pipeline);
    let spans = exported(&pipeline, &exporter);
    let traces: std::collections::BTreeSet<String> = spans
        .iter()
        .map(|s| s.span_context.trace_id().to_string())
        .collect();
    assert_eq!(traces.len(), 2, "{spans:?}");
}

#[test]
fn the_stretch_span_carries_the_required_attributes() {
    let id = job("0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78");
    let (pipeline, exporter) = process();
    work_on(id, &pipeline);
    let spans = exported(&pipeline, &exporter);
    let stretch = by_name(&spans, span::JOB);
    let text = |key: &str| {
        stretch
            .attributes
            .iter()
            .find(|kv| kv.key.as_str() == key)
            .map(|kv| kv.value.as_str().into_owned())
    };
    assert_eq!(text(attr::CORRELATION_ID).as_deref(), Some(CORRELATION));
    assert_eq!(text(attr::JOB_ID), Some(id.to_string()));
    assert_eq!(text(attr::TENANT_ID).as_deref(), Some(TENANT));
}

#[test]
fn the_derived_context_is_the_domain_traceparent() {
    // Anything the domain function derives, the helper uses unchanged.
    for n in 1..=20u8 {
        let id = job(&format!("0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a{n:02x}"));
        let derived = Traceparent::for_job(id);
        let parts: Vec<&str> = derived.as_str().split('-').collect();
        let context = job_trace_context(id);
        assert_eq!(context.trace_id().to_string(), parts[1]);
        assert_eq!(context.span_id().to_string(), parts[2]);
    }
}

#[test]
fn without_a_collector_the_stretch_span_is_a_plain_span() {
    // No OpenTelemetry layer is installed on this thread: the helper must still return a span, and
    // setting the parent must not panic or fail the caller.
    let id = job("0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78");
    let stretch = job_stretch_span(&JobStretch {
        correlation_id: CORRELATION,
        job: id,
        tenant_id: TENANT,
    });
    drop(stretch.enter());
}
