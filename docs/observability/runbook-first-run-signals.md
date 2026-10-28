# Runbook: signals to watch on a first run

- Status: written on 2026-10-28 against the code of that day. Owner: observability. Reviewer: SRE.
- Package: `s1-observability-instrumentation`.
- Related: [conventions](conventions.md) for every name used below, [local stack](../../infra/otel/README.md) for how to look at traces and metrics, [troubleshooting](../operations/troubleshooting.md) for the local deployment.

## What this page is, and what it is not

A first end-to-end run needs five questions answered from telemetry: is a lease stuck, is a stage over its deadline, is a gate blocked by the environment, is a job over its budget, and did the redactor remove something. This page gives, for each, the exact span, metric and log names that exist in the code today, and says plainly which ones do not exist yet.

Two rules for reading it.

- Every name is checked by a test against the conventions page, but **the queries on this page were not run against a live Jaeger or VictoriaMetrics** in the change that wrote it. The stack needs Docker, and none was used. Run each query once on the first real run and correct this page.
- The master prompt asks for spans for every job, stage, agent and tool call, and for metrics on queue depth, duration, error rates, gate failures, retries and spend. It does not list alerts. The five signals here are the first-run list given to the observability package, not a list copied from the master prompt.

"Not yet emitted" means that no production code records the signal. Each such item has a confirmed-gap test, marked as ignored, with the command to run it and the smallest change. The gap numbers (OBS-n) are the ones in those tests.

## Where to look

| What | Where | How |
|---|---|---|
| Traces | Jaeger, `http://127.0.0.1:16686` on the local stack | Pick the service (`factory-worker` or `factory-api`), then search by tag, for example `factory.outcome=timed_out`. To follow one job, search for `factory.job_id=<id>`: every stretch of the job is in one trace. |
| Metrics | VictoriaMetrics, `http://127.0.0.1:8428/vmui` | Metric names are the ones in the conventions table, for example `factory_gate_failures_total`. |
| Logs | Standard error of each process, one JSON object per line | Filter with `jq` on `level`, `target` and `fields.message`. A line written inside a job starts with `correlation_id`. |
| Audit records | The `audit_events` table in PostgreSQL | Not telemetry. Named where a signal below has no span or metric. |

## At a glance

| Signal | Span | Metric | Log | Audit | Missing |
|---|---|---|---|---|---|
| 1. Stuck lease | `factory.attempt`, outcome `lease_lost` | `factory_retries_total` follows | "the sweep recovered attempts" | none | `factory_queue_depth` (OBS-5). Nothing shows a lease while it is stuck. |
| 2. Stage over deadline | `factory.attempt`, outcome `timed_out` | `factory_retries_total` follows | "the sweep recovered attempts" | none | `factory_stage_duration_seconds` (OBS-6); `factory.error_class` on the attempt (OBS-11) |
| 3. Gate blocked by the environment | `factory.gate`, outcome `blocked` | `factory_gate_failures_total` with outcome `blocked` | none | `gate_result` | none for the count; the cause is not in telemetry |
| 4. Cost over budget | none | none | none | `budget_threshold_crossed` | `factory_spend_usd_total` (OBS-7); `factory.agent` span with `factory.cost_usd` (OBS-3) |
| 5. Redaction hit | marker `[REDACTED:` in attribute values and names | none | marker `[REDACTED:`, "log line dropped: redactor unavailable" | `secret_redacted_or_blocked` | a counter (OBS-10) |

## 1. Stuck lease

**What it means.** A worker holds the lease on a stage run and has stopped renewing it, or has lost it. The lease is judged by the database clock. When it expires, the sweep in a worker loop recovers the attempt, and the stage run is retried if its contract allows.

**What exists.**

- Span `factory.attempt` with `factory.outcome` = `lease_lost`. It is on the span of the attempt that lost its lease, and it is recorded by the process that was running the attempt. Attributes to search: `factory.job_id`, `factory.stage_run_id`, `factory.attempt_id`, `factory.attempt_number`, `factory.stage_kind`.
- Log line, level `WARN`, message "the sweep recovered attempts", fields `lease_lost` and `timed_out` (counts). It is written by the worker loop (`apps/worker`, `run.rs`) when a sweep recovered at least one attempt.
- Metric `factory_retries_total{stage}`. It rises when the lost attempt is retried. A rise is a consequence, not a lease signal: other failures raise it too.
- Log lines at the start and end of the loop: "worker loop started", with the `worker` field, and "worker loop stopped", with the number of `attempts` it ran. A worker that is gone shows as a `started` without a `stopped`.

**First check.**

1. Search Jaeger for `factory.outcome=lease_lost` over the last hour. A single one after a worker restart is normal.
2. Look in the worker log for "the sweep recovered attempts". If the sweep ran and recovered nothing while a stage run does not move, the lease has not expired yet: the attempt may still be running.
3. Look for "the sweep failed and will be tried again". A failing sweep leaves expired leases in place.

**Not yet emitted.** `factory_queue_depth{queue="ready_stage_runs"}` (OBS-5). Without it, a queue that is not drained because every worker is stuck looks the same as an idle system. No signal reports the age of a lease while it is stuck. The engine learns of an expired lease only when a sweep or the owner's next write finds it.

## 2. Stage over deadline

**What it means.** An attempt ran past its deadline. The deadline comes from `attempt_timeout_seconds` in the stage contract. The engine ends the attempt with the failure class `TIMED_OUT`, and the stage run is retried if the contract lists that class.

**What exists.**

- Span `factory.attempt` with `factory.outcome` = `timed_out`. Search `factory.outcome=timed_out`. The span's duration is the time the attempt ran.
- Log line, level `WARN`, message "the sweep recovered attempts", field `timed_out`. This one is written when the sweep, and not the owner, found the attempt past its deadline.
- Metric `factory_retries_total{stage}`, as for signal 1.

**First check.**

1. Search `factory.outcome=timed_out` and open the trace. Look at which stage kind it is (`factory.stage_kind`) and how many times it repeated (`factory.attempt_number`). The engine caps the number of attempts.
2. If the same stage times out on every attempt, the timeout in the contract is too short for the work, or the stage is stuck. The trace does not say which.

**Not yet emitted.**

- `factory_stage_duration_seconds{stage,outcome}` (OBS-6). Without it there is no latency percentile per stage and no way to see a stage getting slower before it times out.
- `factory.error_class` on the attempt span (OBS-11). A failed or timed out attempt says what happened but not the failure class.

## 3. Gate blocked by the environment

**What it means.** A gate could not run, or its guard did not hold, so the stage run is blocked and waits for a person. "Blocked" is not "failed": nothing was judged. The usual causes are a missing tool in the sandbox, an unreachable service, or missing evidence.

**What exists.**

- Span `factory.gate` with `factory.outcome` = `blocked`, and `factory.gate_id` naming the gate. It is a child of the `factory.attempt` span of the attempt that evaluated it.
- Metric `factory_gate_failures_total{gate,outcome}` with `outcome="blocked"`. A query for the last fifteen minutes: `sum(increase(factory_gate_failures_total{outcome="blocked"}[15m])) by (gate)`.
- Audit record `gate_result` for the stage run.

**First check.**

1. Find the `factory.gate` span with `factory.outcome=blocked` and read `factory.gate_id`.
2. Compare with `factory_gate_failures_total` by gate. One gate blocked once is a stage waiting for a person. The same gate blocked across jobs points to the environment: the same tool or service is missing everywhere.
3. The cause is not in telemetry. The conventions page keeps error text and tool output out of spans, logs and metrics on purpose. Read the cause in the job's ledger entry for the stage run.

**Not yet emitted.** Nothing is missing for the count. A label for the cause is not in the metric table and would need an architect's review.

## 4. Cost over budget

**What it means.** The spend of a job reached its limit, or a threshold of it. The broker meters every model call through the job token and refuses spend at the ceiling. The engine records a threshold in the audit log, defers a stage run whose job has no budget left, and escalates a stage run to a person with the cause `budget-limit`.

**What exists.** Only records, no span or metric.

- Audit record `budget_threshold_crossed`, written at the end of an attempt whose token crossed the warning fraction of its ceiling (`budgets.thresholds.warn_at_fraction`, 80 percent by default in the engine configuration).
- The escalation to a person with the cause `budget-limit`, in the stage run's events and ledger.
- A stage run that does not start because the job's spend is at or over its limit: the claim defers it with the reason `BudgetExhausted`. Nothing is logged at `info` or higher for this.

**First check.** Query `audit_events` for `budget_threshold_crossed` by job. For spend per job, agent, repository and model, the master prompt points to the evidence ledger and the audit log, as the conventions page says in section 6, rule 4.

**Not yet emitted.**

- `factory_spend_usd_total{provider,stage}` (OBS-7). The engine reads the metered cost of each attempt (`token_cost`) and writes it into the attempt's events, but does not record the metric. No alert on spend can be written until it does.
- The `factory.agent` span with `factory.cost_usd`, `factory.tokens_input` and `factory.tokens_output` (OBS-3). No code opens it.

## 5. Redaction hit

**What it means.** The redactor replaced a secret in text on its way into a log line or a span. One hit means a secret got as far as a call to the logger or the tracer. It is a defect in the call site even though the pipeline stopped it, and it is an incident if the secret was real.

**What exists.**

- The marker `[REDACTED:<id>]`, where the id is a pattern id from `policies/security.yaml` (for example `authorization_header`) or the label of a registered value (for example `broker_keys`). Search the logs for `REDACTED:`. In Jaeger, search by tag value, or open spans whose names or attributes contain it.
- The marker `[REDACTED:scrubber_unavailable]` in a span value, and the log line "log line dropped: redactor unavailable". These mean the redactor **failed**, not that it found something. Treat them as an incident: the value is gone, but the redactor is not working on that input.
- Log line, level `WARN`, message "the final output was dropped because the redactor could not finish" (`crates/runtime`): an agent's output was dropped for the same reason.
- Audit record `secret_redacted_or_blocked`, written by the specification, implementation and documenting stages when they redact or block.
- Log line, level `WARN`, message "telemetry attribute `<key>` is not on the allowlist or has an unknown type; it was dropped", once for each key. It names the key and never the value. It is not a redaction, but it comes from the same guard.

**First check.**

1. Search the last hour of logs for `REDACTED:`. Note the id in the marker.
2. Find the line or span around it. A line has `target`, which names the module that logged it. A span has `factory.job_id`.
3. Fix the call site so the secret is not passed to the logger at all. The redactor is the second line of defense.
4. If the marker is `scrubber_unavailable`, or a "log line dropped" line appears, look for the cause in the redactor's limits (the input was larger than the limit) before anything else.

**Not yet emitted.** A counter of redactions (OBS-10). The guard counts the values it redacted, truncated and dropped, and the counts stay inside the process (`GuardStats`). A search for the marker is the only way to find hits. One known case is not covered by the redactor at all: a second URL with a password on the same log line (OBS-1). Do not rely on the marker to show that no secret reached a log line.

## Keeping this page true

- A name on this page that is not in the conventions page, or a signal marked as existing that no code records, is a defect in this page. The tests `span_openers`, `metric_names` and `telemetry_allowlist` check the names and the openers; they do not read this page. After any change to the engine's spans, metrics or log lines, reread the matching section.
- When a gap is closed, its ignored test passes. Remove the `ignore` marker, delete the "Not yet emitted" paragraph that names it, and move the signal into the "What exists" list with its exact name.
