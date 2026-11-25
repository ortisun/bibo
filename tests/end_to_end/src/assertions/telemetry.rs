//! A11: spans and the correlation id.

use crate::check::{Env, Verdict};
use crate::evidence::RunEvidence;

/// The span name of a stage run.
pub const STAGE_RUN_SPAN: &str = "factory.stage_run";
/// The span name of an attempt.
pub const ATTEMPT_SPAN: &str = "factory.attempt";

/// A11: every attempt has a span whose parent is its stage run span, and the correlation id appears
/// on every event and on every log line of the job: a line written inside one of the job's spans.
/// A line written outside any job carries none, by design, and must not carry this job's.
#[must_use]
pub fn a11(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "A11";
    let spans = &ev.telemetry.spans;
    let mut attempts_seen = 0_usize;
    for run in &ev.stage_runs {
        if run.attempts.is_empty() {
            continue;
        }
        let stage_spans: Vec<_> = spans
            .iter()
            .filter(|span| {
                span.name == STAGE_RUN_SPAN && span.stage_run_id.as_deref() == Some(run.id.as_str())
            })
            .collect();
        // A stage run that waits for a person is claimed again after the answer, and the engine
        // opens a stage run span for each claim. So a run has one span or more, and what must
        // hold is that an attempt hangs under a stage run span of its own run.
        if stage_spans.is_empty() {
            return Verdict::fail(
                ID,
                format!(
                    "the {} run {} has no stage run span, and an attempt needs one above it",
                    run.kind, run.id
                ),
            );
        }
        for attempt in &run.attempts {
            attempts_seen += 1;
            let attempt_spans: Vec<_> = spans
                .iter()
                .filter(|span| {
                    span.name == ATTEMPT_SPAN
                        && span.attempt_id.as_deref() == Some(attempt.id.as_str())
                })
                .collect();
            let [attempt_span] = attempt_spans.as_slice() else {
                return Verdict::fail(
                    ID,
                    format!(
                        "attempt {} of the {} run has {} spans, and it must have one",
                        attempt.id,
                        run.kind,
                        attempt_spans.len()
                    ),
                );
            };
            let under_own_run = stage_spans
                .iter()
                .any(|span| attempt_span.parent_id.as_deref() == Some(span.id.as_str()));
            if !under_own_run {
                return Verdict::fail(
                    ID,
                    format!(
                        "the span of attempt {} has the parent {:?}, which is not a stage run span of the {} run {}",
                        attempt.id, attempt_span.parent_id, run.kind, run.id
                    ),
                );
            }
        }
    }
    if attempts_seen == 0 {
        return Verdict::fail(ID, "no attempt ran, so there is no span to check");
    }
    let correlation = ev.job.correlation_id.as_str();
    let captured = &ev.telemetry.correlated;
    if captured.is_empty() {
        return Verdict::fail(
            ID,
            "no event or log line was captured, so the correlation id cannot be checked",
        );
    }
    if !captured
        .iter()
        .any(|line| line.source == "log" && line.in_job)
    {
        return Verdict::fail(ID, "no log line of the job was captured");
    }
    // A line written outside any job (the token sweep of the worker loop, a start-up message)
    // carries no correlation id by design (`docs/observability/conventions.md`, section 7). It
    // must not carry this job's id either, which would mean the capture misread its place.
    let outside = captured
        .iter()
        .filter(|line| line.source == "log" && !line.in_job)
        .count();
    if let Some(line) = captured
        .iter()
        .find(|line| !line.in_job && line.correlation_id.as_deref() == Some(correlation))
    {
        return Verdict::fail(
            ID,
            format!(
                "the {} {} is recorded as written outside the job but carries the job's correlation id",
                line.source, line.label
            ),
        );
    }
    if let Some(line) = captured
        .iter()
        .filter(|line| line.in_job)
        .find(|line| line.correlation_id.as_deref() != Some(correlation))
    {
        return Verdict::fail(
            ID,
            format!(
                "the {} {} carries the correlation id {:?}, not {correlation}",
                line.source, line.label, line.correlation_id
            ),
        );
    }
    if let Some(record) = ev
        .audit
        .iter()
        .find(|record| record.correlation_id.as_deref() != Some(correlation))
    {
        return Verdict::fail(
            ID,
            format!(
                "audit event {} ({}) carries the correlation id {:?}, not {correlation}",
                record.seq, record.action, record.correlation_id
            ),
        );
    }
    Verdict::pass(
        ID,
        format!(
            "{attempts_seen} attempt span(s) hang under their stage run spans, and all {} captured events and lines of the job and {} audit events carry the correlation id ({outside} line(s) written outside any job carry none, by design)",
            captured.len() - outside,
            ev.audit.len()
        ),
    )
}
