//! Sends one small, fake job to whatever collector the environment names.
//!
//! This is the manual check for the local stack in `infra/otel`. It uses only fake identifiers.
//!
//! ```text
//! OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 cargo run -p factory-observability --example emit_sample
//! ```

use factory_observability::spans::{self, Agent, Attempt, Gate, Job, StageRun, ToolCall};
use factory_observability::telemetry::{TelemetryConfig, init};

const CORRELATION: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77";
const JOB: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78";

fn main() {
    let config = TelemetryConfig::from_env("factory-sample", env!("CARGO_PKG_VERSION"))
        .unwrap_or_else(|error| panic!("bad telemetry settings: {error}"));
    let guard = init(&config).unwrap_or_else(|error| panic!("cannot start telemetry: {error}"));

    run_sample_job();

    // The job span has ended by now, so the flush includes it.
    match guard.flush() {
        Ok(()) => tracing::info!("telemetry flushed"),
        Err(error) => tracing::error!("telemetry was not flushed: {error}"),
    }
}

fn run_sample_job() {
    let job = spans::job_span(&Job {
        correlation_id: CORRELATION,
        job_id: JOB,
        tenant_id: "sample-tenant",
    });
    let _job = job.enter();
    tracing::info!("sample job admitted");

    let stage_run = spans::stage_run_span(&StageRun {
        correlation_id: CORRELATION,
        job_id: JOB,
        stage_run_id: "sample-stage-run",
        stage_kind: "IMPLEMENTATION",
    });
    {
        let _stage_run = stage_run.enter();
        let attempt = spans::attempt_span(&Attempt {
            correlation_id: CORRELATION,
            job_id: JOB,
            stage_run_id: "sample-stage-run",
            attempt_id: "sample-attempt",
            attempt_number: 1,
        });
        {
            let _attempt = attempt.enter();
            let agent = spans::agent_span(&Agent {
                correlation_id: CORRELATION,
                job_id: JOB,
                attempt_id: "sample-attempt",
                agent_id: "software_engineer",
            });
            {
                let _agent = agent.enter();
                let tool = spans::tool_call_span(&ToolCall {
                    correlation_id: CORRELATION,
                    job_id: JOB,
                    attempt_id: "sample-attempt",
                    tool_name: "read_file",
                });
                spans::record_outcome(&tool, "succeeded");
            }
            spans::record_outcome(&agent, "succeeded");
            tracing::info!(
                monotonic_counter.factory_spend_usd_total = 0.0125f64,
                provider = "anthropic",
                stage = "IMPLEMENTATION"
            );
            spans::record_outcome(&attempt, "succeeded");
        }
        let gate = spans::gate_span(&Gate {
            correlation_id: CORRELATION,
            job_id: JOB,
            stage_run_id: "sample-stage-run",
            gate_id: "scope-check",
        });
        spans::record_outcome(&gate, "failed");
        tracing::info!(
            monotonic_counter.factory_gate_failures_total = 1u64,
            gate = "scope-check",
            outcome = "failed"
        );
    }
    tracing::info!(
        histogram.factory_stage_duration_seconds = 42.5f64,
        stage = "IMPLEMENTATION",
        outcome = "failed"
    );
    tracing::info!(
        monotonic_counter.factory_stage_runs_total = 1u64,
        stage = "IMPLEMENTATION",
        outcome = "failed"
    );
    tracing::info!(
        monotonic_counter.factory_retries_total = 1u64,
        stage = "IMPLEMENTATION"
    );
    tracing::info!(gauge.factory_queue_depth = 3i64, queue = "ready_stage_runs");
    tracing::info!("sample job finished");
}
