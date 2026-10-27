# Observability conventions

- Status: Slice 0 baseline. The names and tables below are checked by tests in `crates/observability`. No factory service records them yet; the call sites arrive in Slice 1.
- Owner: observability. Reviewer: software architect.
- Package: `s0-telemetry-baseline`. The Slice 1 package `s1-observability-instrumentation` verifies the call sites against this page.
- Related: architecture decision record (ADR) [0004](../adr/0004-event-model.md) for domain events, [secrets and credentials](../security/secrets-and-credentials.md) for redaction, [`policies/security.yaml`](../../policies/security.yaml) for the secret patterns.

## 1. What this page fixes

The factory exposes two kinds of telemetry: traces, and metrics that VictoriaMetrics can store. It also writes diagnostic logs. This page fixes the names, the types and the rules for all three, so that a person reading a trace and a dashboard sees the same words. Spans and metrics travel from a program to a collector in the OpenTelemetry Protocol (OTLP).

The tables on this page are the contract. The tests in `crates/observability` read this file and fail when a table and the code disagree. If you change a name, change both in one commit.

## 2. Naming rules

1. Span names and custom attribute keys start with `factory.` and continue in lower case with underscores, for example `factory.stage_run`. One dot, no camel case.
2. The only keys without the prefix are the OpenTelemetry standard keys listed in the attribute table. Today that is `error.type`.
3. Metric names start with `factory_`, use lower case with underscores, and end with their unit when they have one: `_seconds`, `_usd_total`. Counters end with `_total`. Gauges and histograms never do.
4. Metric label names are single lower case words such as `stage` or `outcome`. They never repeat an attribute key, and they never name an identifier.
5. The unit goes in the metric's unit field too, using the unit code in the metric table. The name carries the suffix as well, so the name reads the same in every backend, whichever way that backend translates units.
6. A name is never reused for a different meaning. To change what a name means, add a new name and retire the old one in a later release.

## 3. Spans

Each job produces one tree of spans. The job span is the root, a stage run hangs off it, an attempt hangs off the stage run, and the agent, tool call and gate spans hang off the attempt or the stage run.

A span must carry every attribute in its "required" column when it ends. Required attributes that are only known at the end of the work, such as `factory.outcome`, are set just before the span closes.

<!-- table:spans -->
| Span | Required attributes | Meaning |
|---|---|---|
| `factory.job` | `factory.correlation_id`, `factory.job_id`, `factory.tenant_id` | One request from admission to a terminal state. |
| `factory.stage_run` | `factory.correlation_id`, `factory.job_id`, `factory.stage_run_id`, `factory.stage_kind` | One execution of one stage kind. |
| `factory.attempt` | `factory.correlation_id`, `factory.job_id`, `factory.stage_run_id`, `factory.attempt_id`, `factory.attempt_number`, `factory.outcome` | One try at a stage run, owned by one worker. |
| `factory.agent` | `factory.correlation_id`, `factory.job_id`, `factory.attempt_id`, `factory.agent_id`, `factory.outcome` | One agent invocation inside an attempt. |
| `factory.tool_call` | `factory.correlation_id`, `factory.job_id`, `factory.attempt_id`, `factory.tool_name`, `factory.outcome` | One tool call made by an agent. |
| `factory.gate` | `factory.correlation_id`, `factory.job_id`, `factory.stage_run_id`, `factory.gate_id`, `factory.outcome` | One gate evaluation inside a stage run. |
<!-- /table:spans -->

## 4. Attributes

An attribute is a key and a value on a span. Only the keys in this table are exported. The exporter drops any other key before it leaves the process. This is the attribute allowlist that check ST-07 in the [negative test catalog](../security/negative-test-catalog.md) refers to.

"Unbounded" means the attribute can take an unlimited number of values, such as an identifier or a measurement. It belongs on spans and in logs. It never belongs on a metric. Section 6 explains why.

<!-- table:attributes -->
| Key | Type | Cardinality | Spans | Meaning |
|---|---|---|---|---|
| `factory.correlation_id` | string | unbounded | `factory.job`, `factory.stage_run`, `factory.attempt`, `factory.agent`, `factory.tool_call`, `factory.gate` | Shared by every span, log line and domain event of one job. |
| `factory.tenant_id` | string | unbounded | `factory.job` | The tenant that owns the job. |
| `factory.job_id` | string | unbounded | `factory.job`, `factory.stage_run`, `factory.attempt`, `factory.agent`, `factory.tool_call`, `factory.gate` | The job. |
| `factory.stage_run_id` | string | unbounded | `factory.stage_run`, `factory.attempt`, `factory.gate` | The stage run. |
| `factory.attempt_id` | string | unbounded | `factory.attempt`, `factory.agent`, `factory.tool_call` | The attempt. |
| `factory.stage_kind` | string | bounded | `factory.stage_run`, `factory.attempt`, `factory.gate` | The stage kind, such as INTAKE, in the spelling of the state machine file. |
| `factory.attempt_number` | int | bounded | `factory.attempt` | Which try this is within the stage run, starting at 1. The engine caps it. |
| `factory.agent_id` | string | bounded | `factory.agent` | The agent identifier from the agent registry. |
| `factory.model` | string | bounded | `factory.agent` | The model name the broker reports. |
| `factory.tool_name` | string | bounded | `factory.tool_call` | The tool, taken from the stage tool profile. |
| `factory.gate_id` | string | bounded | `factory.gate` | The gate identifier from the gate catalog. |
| `factory.outcome` | string | bounded | `factory.job`, `factory.stage_run`, `factory.attempt`, `factory.agent`, `factory.tool_call`, `factory.gate` | How the work ended. One of the outcome values below. |
| `factory.error_class` | string | bounded | `factory.job`, `factory.stage_run`, `factory.attempt`, `factory.agent`, `factory.tool_call`, `factory.gate` | The failure class the engine recorded, when the work failed. |
| `factory.prompt_sha256` | string | unbounded | `factory.agent` | Hex digest of the prompt. The prompt itself is stored as an artifact. |
| `factory.tool_args_sha256` | string | unbounded | `factory.tool_call` | Hex digest of the tool arguments. |
| `factory.tokens_input` | int | unbounded | `factory.agent` | Input tokens the broker metered for this invocation. |
| `factory.tokens_output` | int | unbounded | `factory.agent` | Output tokens the broker metered for this invocation. |
| `factory.cost_usd` | double | unbounded | `factory.agent` | Cost in United States dollars the broker metered for this invocation. |
| `error.type` | string | bounded | `factory.job`, `factory.stage_run`, `factory.attempt`, `factory.agent`, `factory.tool_call`, `factory.gate` | The standard error.type key. A short error kind, never a message. |
<!-- /table:attributes -->

### Event attributes

A span can carry events, which are the `tracing` events logged inside it. The tracing layer adds two attributes to every span event. They are allowed on events and nowhere else.

<!-- table:event-attributes -->
| Key | Meaning |
|---|---|
| `level` | The severity of the event, such as `WARN`. |
| `target` | The module path of the code that logged the event. |
<!-- /table:event-attributes -->

### Outcome values

`factory.outcome` and the metric label `outcome` take one of these values. Each is the lower case form of a state in the state machine file or of a gate outcome in the gate report schema.

<!-- table:outcomes -->
| Value | Used for |
|---|---|
| `passed` | A gate or stage run that passed. |
| `failed` | A gate, stage run or attempt that failed. |
| `blocked` | A gate or stage run that could not run or was stopped by policy and waits for a person. |
| `not_applicable` | A gate with nothing to check on this change. |
| `succeeded` | An attempt or agent invocation that finished its work. |
| `timed_out` | An attempt that ran past its deadline. |
| `lease_lost` | An attempt whose worker lost its lease. |
| `cancelled` | Work that was cancelled. |
| `denied` | A tool call that policy refused. |
| `rework_requested` | A stage run that sent the job back for rework. |
<!-- /table:outcomes -->

### Recording attributes

- Record integers as `i64`. The `tracing-opentelemetry` layer used here (version 0.34) turns an unsigned field such as a `u64` into a string. A test in `crates/observability` pins that behavior, so an upgrade that fixes it will say so.
- Declare a field that is only known at the end with `tracing::field::Empty` when the span is created, and fill it in with `Span::record`. `tracing` cannot add a field that was not declared at creation.
- Do not record free text. Section 8 lists what is left out on purpose.

## 5. Metrics

Metrics are for questions about the whole system over time: how deep is the queue, how long do stages take, how often do gates fail, what did we spend. They go to VictoriaMetrics.

<!-- table:metrics -->
| Name | Type | Unit | Labels | Meaning |
|---|---|---|---|---|
| `factory_queue_depth` | gauge | {stage_run} | `queue` | Stage runs that are ready and waiting for a worker, by queue. |
| `factory_stage_duration_seconds` | histogram | s | `stage`, `outcome` | Wall-clock time from the start of a stage run to its end, by stage kind and outcome. |
| `factory_stage_runs_total` | counter | {stage_run} | `stage`, `outcome` | Stage runs that ended, by stage kind and outcome. The error rate is the share with outcome failed. |
| `factory_gate_failures_total` | counter | {gate_failure} | `gate`, `outcome` | Gate evaluations that ended failed or blocked, by gate and outcome. |
| `factory_retries_total` | counter | {retry} | `stage` | Retries scheduled after a retryable attempt failure, by stage kind. |
| `factory_spend_usd_total` | counter | {USD} | `provider`, `stage` | Model spend in United States dollars as metered by the broker, by provider and stage kind. |
<!-- /table:metrics -->

The stage duration histogram has these upper bounds in seconds: 1, 5, 15, 30, 60, 120, 300, 600, 1200, 1800 and 3600. A longer stage lands in the overflow bucket.

Two queries that answer common questions:

- Error rate of a stage over five minutes: the rate of `factory_stage_runs_total` with `outcome="failed"` divided by the rate of the same metric without that filter.
- Spend per hour by provider: the increase of `factory_spend_usd_total` over one hour, summed by `provider`.

### How to record a metric

Write a `tracing` event whose field name starts with the instrument kind and ends with the metric name. Every other field of the event is a label. Do not add a `target:` argument, because the `tracing` macros cannot parse a dotted field name after one.

```rust
tracing::info!(monotonic_counter.factory_retries_total = 1u64, stage = "IMPLEMENTATION");
tracing::info!(histogram.factory_stage_duration_seconds = 42.5f64, stage = "VALIDATION", outcome = "passed");
tracing::info!(gauge.factory_queue_depth = 3i64, queue = "ready_stage_runs");
```

Use `monotonic_counter.` for counters, `histogram.` for histograms and `gauge.` for gauges. Crates that may only depend on `tracing` can record metrics this way.

The pipeline does not trust the call site. It checks each event against the table above:

- A metric name that is not in the table is dropped. So is a name recorded with the wrong kind, such as a histogram named like a counter.
- The unit, the description and the histogram buckets come from the table, not from the call site.
- Only the labels listed for that metric are kept. Any other field on the event is removed before the values are added up.

A metric event is not a log line and not a span event. The log layer and the span layer skip it.

### Labels

<!-- table:labels -->
| Label | Max values | Meaning |
|---|---|---|
| `stage` | 16 | The stage kind, spelled as in the state machine file, such as INTAKE. |
| `outcome` | 12 | One of the outcome values on the conventions page. |
| `gate` | 48 | The gate identifier from the gate catalog. |
| `provider` | 8 | The model provider the broker reports, such as anthropic. |
| `queue` | 4 | The name of a work queue, such as ready_stage_runs. |
<!-- /table:labels -->

"Max values" is the size of the closed set the label draws from, with some room to grow. It is not a count of values in use today.

## 6. Cardinality rules

Cardinality is the number of different label combinations a metric holds. A metrics database stores one time series for each combination. A label that takes a new value for every job, such as a job identifier, creates a new series for every job. The series count grows without limit, memory and disk grow with it, and queries slow down until the database fails. That is why identifiers never go on metrics.

The rules:

1. **Identifiers go on spans and in logs, never on metrics.** The correlation id, the tenant, job, stage run and attempt identifiers, digests and measurements such as token counts are "unbounded" in the attribute table. A trace or a log search finds them. A metric does not carry them.
2. **A metric label draws from a small closed set.** Each label in the label table has a maximum size, and no label may allow more than 64 values. A label that needs more belongs on a span.
3. **Each metric states how many label combinations it may hold**, and that number may not exceed the product of its labels' sizes or 500. The six metrics together fit in 5,000 time series, counting each histogram bucket as one.
4. **Spend and queue questions per job are answered from the ledger and from traces.** The master prompt asks for cost per task, job, agent, repository, model and organization. Those views come from the evidence ledger in PostgreSQL and from span attributes such as `factory.cost_usd`. The metric holds spend by provider and stage only.
5. **The pipeline enforces the rules even when a call site breaks them.** Unlisted labels are removed. A metric that still grows past its limit has the excess folded into one overflow series, marked with the label `otel.metric.overflow`, and no count is lost. An overflow series on a dashboard is a defect to fix at the call site.

## 7. Logs, domain events and the correlation id

The factory writes two different things and keeps them apart.

| | Diagnostic logs | Domain events |
|---|---|---|
| Purpose | Help a person understand what a process was doing | Record that a state change happened, for other components |
| Where they go | Standard error of each process, as JSON lines | The `outbox` table in the same transaction as the change, later a JetStream message stream |
| Guarantee | None. Lines may be dropped, sampled or rotated away | At least once delivery, ordered per aggregate, kept long term |
| Who may depend on them | Nobody. No code reads logs to decide anything | Consumers, the dashboard and the audit trail |
| Contents | Free text and `factory.` fields, redacted | Identifiers and hashes under the event schema, blocked if a secret matches |

[ADR 0004](../adr/0004-event-model.md) describes domain events. Nothing in this crate writes one.

A log line is one JSON object. When a line is written inside a job span, or inside a span below it, the line starts with the field `correlation_id`. The value is the same one that domain events carry in their `correlation_id` field and that spans carry as `factory.correlation_id`, so one search finds a job in the logs, the events and the traces. Lines written outside a job, such as start-up messages, have no such field.

```json
{"correlation_id":"0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77","timestamp":"2026-10-27T08:15:14.502266Z","level":"INFO","fields":{"message":"stage run started","factory.stage_kind":"INTAKE"},"target":"factory_workflow::engine"}
```

The id must be a lower case UUID. A value in any other form is ignored and never written, so a log line cannot be forged through a bad id.

Log fields use the same names as span attributes, plus `message` and `correlation_id`. Any other field name is outside the allowlist. The one exception is the lines that the OpenTelemetry libraries write about their own failures, such as a collector that cannot be reached. They use the library's field names, such as `name`, `operation` and `error`. They describe the telemetry pipeline and hold no factory data.

## 8. What is deliberately not recorded

Telemetry leaves the process and is kept by other systems. The default is to record identifiers and hashes and nothing that a person typed or a model produced.

| Not recorded | Why | What is recorded instead |
|---|---|---|
| Secrets and credentials: tokens, keys, passwords, connection strings | A leak in telemetry spreads to every system that stores traces and logs | Nothing. A match is replaced by a placeholder that names the pattern |
| Issue text and pull request text | It is untrusted input and may hold private details | The issue number and the job identifier |
| Model prompts and model output | Large, private and may hold secrets | `factory.prompt_sha256`, a digest. The text is an artifact in the artifact store |
| Tool arguments and tool output | They can hold file contents and credentials | `factory.tool_args_sha256`, a digest |
| Source code and diffs | Private to the customer | The path count and byte count, where useful, as numbers |
| Error messages and stack traces | They hold file paths, query text and internals | `factory.error_class` and `error.type`, short kinds from a closed set |
| Request headers and cookies | They carry credentials | Nothing |

Four mechanisms enforce this, each tested:

1. **An allowlist of names.** Only the attribute keys in the table in section 4 leave the process. The exporter drops any other key and counts the drop. A first drop of each key is noted in the diagnostic log, by key name only. Check ST-07 in the [negative test catalog](../security/negative-test-catalog.md) is this rule.
2. **A scrubber.** Every string that remains, and every span name, event name and log line, passes through a scrubber that removes the secret patterns listed under `secrets.patterns` in [`policies/security.yaml`](../../policies/security.yaml). Each match is replaced by `[REDACTED:` followed by the pattern id and a closing bracket. A test reads the policy file and fails if the scrubber and the policy list different patterns. The entropy heuristic and the registry of the factory's own secret values are not applied here; the redaction work package adds them.
3. **A length limit.** A string attribute longer than 256 bytes is cut and ends with `[TRUNCATED]`. Identifiers and digests fit. A prompt or an issue body does not. The scrubber runs first, so a secret that straddles the cut is removed whole.
4. **Fail closed.** If the scrubber cannot run, the value is replaced and the original is never written. The text of an error status is always blanked.

These mechanisms are a second line of defense. The first line is not putting the secret in the call in the first place.

## 9. Starting telemetry in a program

A binary starts telemetry once, early in `main`, and keeps the guard until it exits. Library crates never start it.

```rust
let config = TelemetryConfig::from_env("factory-worker", env!("CARGO_PKG_VERSION"))?;
let _telemetry = factory_observability::telemetry::init(&config)?;
```

| Variable | Meaning | Default |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Base URL of the collector, such as `http://localhost:4318`. The program adds `/v1/traces` and `/v1/metrics`. | Not set: nothing is exported |
| `OTEL_SDK_DISABLED` | `true` turns export off even when an endpoint is set. | Not set |
| `FACTORY_LOG` | Which log lines are written, in the `RUST_LOG` syntax. | `info` |
| `FACTORY_ENV` | The deployment environment, named on every span and metric. | `local` |

How it behaves:

- **It is safe to call twice.** The first call installs the pipeline and returns the guard that owns it. Later calls change nothing and return a guard that owns nothing, even after the first guard is dropped. A process can install its global subscriber only once.
- **With no collector, the process still logs.** Spans and metric events cost almost nothing, and nothing is sent.
- **A collector that is down does not stop the process.** The exporters work on their own threads. After three retries the SDK writes a warning and an error line to the diagnostic log, and the spans and metrics of that interval are lost. `flush` returns the error to the caller. This was observed with the sample program pointed at a port where nothing listens.
- **The collector address is checked when it is read.** Only plain `http://` is accepted, because this build has no TLS support. An address with a user name, password, query or fragment is refused, and the error message does not repeat the address.
- **Dropping the first guard flushes.** It sends what is buffered and stops the exporters. Call `flush` on the guard earlier to send on demand.
- **It can be called from async code.** The HTTP client is built on its own thread, so it does not clash with a running Tokio runtime.

## 10. Local stack

[`infra/otel/`](../../infra/otel/README.md) holds a collector configuration, a Docker Compose file that starts the collector, VictoriaMetrics and Jaeger on the loopback address, and a script that checks the configuration with the pinned collector image. Its README says what was verified and when.

## 11. Dependencies

The crate depends only on the external crates that `docs/architecture/crate-dependency-rules.json` allows for `observability`. Versions are pinned in `crates/observability/Cargo.toml`. Release dates are from crates.io and were read on 2026-10-27.

| Crate | Version | Released | Why |
|---|---|---|---|
| `tracing` | 0.1.44 | 2025-12-18 | The standard instrumentation API, and the only telemetry crate that application and adapter crates may use. |
| `tracing-subscriber` | 0.3.23 | 2026-03-13 | Log formatting, filters and layers. Default features are off. It uses `std`, `registry`, `fmt`, `json` and `env-filter`. |
| `tracing-opentelemetry` | 0.34.0 | 2026-09-23 | Turns `tracing` spans and metric events into OpenTelemetry data. It requires `opentelemetry` 0.33, which fixes the version of the next three. |
| `opentelemetry` | =0.33.1 | 2026-10-09 | The API. |
| `opentelemetry_sdk` | =0.33.1 | 2026-10-09 | Providers, processors, views and the in-memory test exporters. |
| `opentelemetry-otlp` | =0.33.1 | 2026-10-09 | The OTLP exporters, over HTTP with protobuf bodies. |

The three OpenTelemetry crates are pinned with an exact version because they are 0.x crates that must move together. An upgrade changes all of them and `tracing-opentelemetry` in one commit and re-runs the whole test suite.

Choices that go beyond the defaults:

- **OTLP over HTTP with a blocking client, not gRPC.** The gRPC exporter needs `tokio` and `tonic`. The HTTP exporter with a blocking client runs on the batch processor's own thread, so this crate needs no async runtime. The dependency rules do not list `tokio` for `observability`. It is still in the build as a dependency of the HTTP client, but this crate does not name it.
- **No TLS.** The exporter is built without a TLS feature, which keeps `rustls` and its cryptography libraries out of the build. The collector is expected on the same host or on a private network. A decision to send telemetry over the open network needs a TLS feature and a review.
- **The SDK's `internal-logs` feature is on.** Without it a dead collector fails silently. With it the SDK writes export failures to the diagnostic log through `tracing`.
- **The SDK's `spec_unstable_metrics_views` feature is on.** It provides the call that removes unlisted labels from a metric. The name says the specification for that part is not final, so an upgrade of the SDK must re-run the label tests in `crates/observability/tests/metrics.rs`.

The crate does not use the `regex` crate, because the dependency rules do not allow it here. The secret scrubber is written by hand instead, and a test keeps it equal to the patterns in the security policy.

## 12. What is not done

These items are known gaps, not oversights.

- **One redactor.** The security documents call for a single `Redactor` in `domain::redaction`, with a registry of the factory's own secret values and a sliding window for secrets split across chunks. That work belongs to package `s1-redaction`. Until it lands, this crate carries its own scrubber behind the `Scrub` trait. When it lands, the composition root passes the real redactor in, and this crate's scrubber can be removed.
- **Peer crates cannot use these constants.** The dependency rules forbid a dependency between two crates in the application and adapter ring. `workflow`, `runtime`, `sandbox` and the others therefore write the same strings in their own `tracing` calls. The tables here are the reference, and package `s1-observability-instrumentation` checks the spans they produce with `check_span_shape`. A repository-wide scan for ST-07 does not exist yet.
- **No trace context in domain events.** The event schema has an optional `traceparent`. Writing it from the current span, and continuing a trace from it after a restart, is not done. A job outlives any one process, so the job span cannot be one long-lived span in memory. How to link the pieces is a Slice 1 design question.
- **No OTLP logs.** Logs go to standard error. The policy names `otel_log_records` as a sink, and the pipeline would need the `opentelemetry-appender-tracing` crate, which is not on the allow list.
- **No alert rules or dashboards.** This package fixes the names and the data. Rules and dashboards come after the first end-to-end run shows what values the metrics take.
- **Example only.** The `emit_sample` example in the crate sends fake identifiers to a collector. No factory service records these spans or metrics yet.
