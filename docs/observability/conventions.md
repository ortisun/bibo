# Observability conventions

- Status: Slice 1. The names and tables below are checked by tests in `crates/observability` and by the repository-wide ST-07 scan in `xtask`. The redactor is connected and a job is one trace (sections 3 and 12). The decisions are those of [ADR 0013](../adr/0013-telemetry-wiring.md), which is pending human confirmation as item 14 of [ADR 0009](../adr/0009-operating-defaults-pending-confirmation.md).
- Owner: observability. Reviewer: software architect.
- Packages: `s0-telemetry-baseline` fixed the names, `s1-telemetry-wiring` connected the redactor and added the job trace context, and `s1-observability-instrumentation` verifies the call sites against this page.
- Related: architecture decision record (ADR) [0004](../adr/0004-event-model.md) for domain events, [0013](../adr/0013-telemetry-wiring.md) for the telemetry wiring, [secrets and credentials](../security/secrets-and-credentials.md) for redaction, [`policies/security.yaml`](../../policies/security.yaml) for the secret patterns.

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

Each job produces one trace. In it, each stretch of work on the job has a `factory.job` span (see "One job, one trace" below). A stage run hangs off that span, an attempt hangs off the stage run, and the agent, tool call and gate spans hang off the attempt or the stage run.

### One job, one trace

A job lives for hours or days, across restarts and across the API and the worker, and a span is exported only when it ends. No span can last for the whole job, so a job is made one trace in another way: its trace context is derived from the job id (ADR 0013, decision 3).

- The **trace id** is the 32 lowercase hex characters of the job's UUID. The **root span id** is the first 16 hex characters of the SHA-256 of the text `factory.job` followed by the job id. The flags are `01`. `domain::values::Traceparent::for_job` computes it, and any process can, so nothing is stored.
- Each process that works on a job opens a `factory.job` span for its **stretch** of work: the API while it handles a command on the job, the worker while it holds a claim. The stretch span's remote parent is the derived context. Use `factory_observability::spans::job_stretch_span`, which takes the job id as a `JobId` so the trace cannot be derived from a string by mistake. The composition roots call it through `factory_composition::telemetry::job_stretch`.
- The derived root span is never exported. A backend shows the stretches as children of a missing parent inside one trace. A job therefore has several `factory.job` spans in one trace, one for each stretch, and a search by `factory.job_id` finds them all.
- The engine writes the same derived `traceparent` into each outbox event. It names the job's trace, not the span that caused the event; `causation_id` does that.
- Stage run, attempt, agent, tool call and gate spans that the engine creates inside the stretch take it as their parent and join the trace. The engine crate cannot import this crate, so the stretch is opened by its caller.
- A stage run outlives a process and a worker, and no span can last that long. So each attempt that the engine runs opens a `factory.stage_run` span of its own under the stretch, and the attempt hangs from it. A stage run that is retried shows as several `factory.stage_run` spans with the same `factory.stage_run_id`; search by that identifier to see them all. The span has `factory.outcome` only when the attempt ended the stage run (`passed`, `failed`, `blocked` or `rework_requested`), read from the status the run holds after the commit. A run that is retried or that waits for a person has no outcome on that span.
- Without a collector the stretch is a plain `tracing` span and nothing is exported.

A span must carry every attribute in its "required" column when it ends. Required attributes that are only known at the end of the work, such as `factory.outcome`, are set just before the span closes.

<!-- table:spans -->
| Span | Required attributes | Meaning |
|---|---|---|
| `factory.job` | `factory.correlation_id`, `factory.job_id`, `factory.tenant_id` | One stretch of work on a job in one process. All stretches of a job are in one trace. |
| `factory.stage_run` | `factory.correlation_id`, `factory.job_id`, `factory.stage_run_id`, `factory.stage_kind` | One execution of one stage kind. |
| `factory.attempt` | `factory.correlation_id`, `factory.job_id`, `factory.stage_run_id`, `factory.attempt_id`, `factory.attempt_number`, `factory.outcome` | One try at a stage run, owned by one worker. |
| `factory.agent` | `factory.correlation_id`, `factory.job_id`, `factory.attempt_id`, `factory.agent_id`, `factory.outcome` | One agent invocation inside an attempt. |
| `factory.tool_call` | `factory.correlation_id`, `factory.job_id`, `factory.attempt_id`, `factory.tool_name`, `factory.outcome` | One tool call made by an agent. |
| `factory.gate` | `factory.correlation_id`, `factory.job_id`, `factory.stage_run_id`, `factory.gate_id`, `factory.outcome` | One gate evaluation inside a stage run. |
| `factory.troubleshooting_run` | `factory.troubleshooting_run_id`, `factory.trigger`, `factory.result` | One run of the troubleshooter, outside every job: the probes that tripped, the agent run and the issue decisions. |
| `factory.probe` | `factory.troubleshooting_run_id`, `factory.probe_id`, `factory.result` | One deterministic probe of the troubleshooter. |
| `factory.triage_issue` | `factory.troubleshooting_run_id`, `factory.issue_action` | One decision of the troubleshooter about the triage issue of a finding. |
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
| `factory.troubleshooting_run_id` | string | unbounded | `factory.troubleshooting_run`, `factory.probe`, `factory.triage_issue` | The troubleshooting run. A run is not a job. |
| `factory.trigger` | string | bounded | `factory.troubleshooting_run` | Why the troubleshooting run started: probe or sweep. |
| `factory.result` | string | bounded | `factory.troubleshooting_run`, `factory.probe` | How a troubleshooting run or a probe ended, such as healthy, evidence_mismatch, tripped or no_data. |
| `factory.probe_id` | string | bounded | `factory.probe` | The probe id from the troubleshooting policy. |
| `factory.issue_action` | string | bounded | `factory.triage_issue` | What the troubleshooter did about a finding: opened, commented, unchanged, deferred or dry_run. |
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
| `factory_redactions_total` | counter | {redaction} | `kind` | Values the attribute guard redacted, truncated or dropped before a span left the process, by kind. |
| `factory_troubleshooting_runs_total` | counter | {run} | `trigger`, `result` | Troubleshooting runs that ended, by trigger and result. |
| `factory_probe_results_total` | counter | {probe_result} | `probe`, `result` | Results of the troubleshooter's probes, by probe and result. |
| `factory_gateway_calls_total` | counter | {call} | `upstream`, `result` | Calls of the troubleshooter's MCP gateway, probes and agent together, by upstream and result. |
| `factory_triage_issues_total` | counter | {issue} | `action` | The troubleshooter's decisions about triage issues, by action. |
<!-- /table:metrics -->

`factory_redactions_total` was added in the telemetry gap fix (gap OBS-10) at the lead's approval; architect confirmation pending. Its one label, `kind`, takes the fixed words `redacted`, `truncated` and `dropped`, and no other value. It is raised where the guard raises its own counts (`GuardStats`), and only the kind is passed to it: never the matched text, the pattern id, the key or the value, so no customer value can become a label. `dropped` also counts the values the guard replaced because the scrubber failed (`GuardSnapshot::scrub_failures`), since the original is not passed on in either case. The metric covers the span guard only. The log writer's own redactions are not counted yet.

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
| `kind` | 4 | What the attribute guard did to a value: redacted, truncated or dropped. |
| `trigger` | 4 | Why a troubleshooting run started: probe or sweep. |
| `result` | 16 | How a troubleshooting run, a probe or a gateway call ended, in the troubleshooter's closed words. |
| `probe` | 32 | The probe id from the troubleshooting policy. |
| `upstream` | 4 | The upstream of the MCP gateway: datadog, victoriametrics or postgres. |
| `action` | 8 | What the troubleshooter did about a finding: opened, commented, unchanged, deferred or dry_run. |
<!-- /table:labels -->

"Max values" is the size of the closed set the label draws from, with some room to grow. It is not a count of values in use today.

## 6. Cardinality rules

Cardinality is the number of different label combinations a metric holds. A metrics database stores one time series for each combination. A label that takes a new value for every job, such as a job identifier, creates a new series for every job. The series count grows without limit, memory and disk grow with it, and queries slow down until the database fails. That is why identifiers never go on metrics.

The rules:

1. **Identifiers go on spans and in logs, never on metrics.** The correlation id, the tenant, job, stage run and attempt identifiers, digests and measurements such as token counts are "unbounded" in the attribute table. A trace or a log search finds them. A metric does not carry them.
2. **A metric label draws from a small closed set.** Each label in the label table has a maximum size, and no label may allow more than 64 values. A label that needs more belongs on a span.
3. **Each metric states how many label combinations it may hold**, and that number may not exceed the product of its labels' sizes or 500. The seven metrics together fit in 5,000 time series, counting each histogram bucket as one.
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
2. **The redactor.** Every string that remains, and every span name, event name and log line, passes through the factory's one redactor, `domain::redaction::Redactor`, behind the `Scrub` trait. The composition root builds it from the loaded security policy ([`policies/security.yaml`](../../policies/security.yaml): the patterns, the entropy settings, the encodings) and registers the factory's own secret values with it, in every encoding the policy lists. Each match is replaced by `[REDACTED:` followed by the pattern id or the label of the registered value and a closing bracket. This crate holds no pattern of its own; an earlier copy of the patterns and the test that kept it equal to the policy are gone. A value registered after start-up, such as a job token the broker issues, is found at once, because the pipeline holds the same redactor. The entropy heuristic only raises a flag in the redactor and does not change the text.
3. **A length limit.** A string attribute longer than 256 bytes is cut and ends with `[TRUNCATED]`. Identifiers and digests fit. A prompt or an issue body does not. The scrubber runs first, so a secret that straddles the cut is removed whole.
4. **Fail closed.** If the redactor fails on a value (the value is larger than its limit, or its checks failed), a span value is replaced by `[REDACTED:scrubber_unavailable]`, a log line is replaced by a fixed error line, and the original is never written. The text of an error status is always blanked.

There is no way to start the pipeline without a scrubber. `TelemetryConfig::new` and its two readers, `from_env` and `from_lookup`, take it as an argument; there is no default and no setter, so a binary that has no redactor does not compile. Tests in `crates/observability` pin the shape of these functions. Other tests put canary secrets into a span attribute, a span name, a span event, an error status and log lines (negative test NT-SEC-01, telemetry sinks) and read what an in-memory exporter and a captured writer received.

These mechanisms are a second line of defense. The first line is not putting the secret in the call in the first place.

## 9. Starting telemetry in a program

A binary starts telemetry once, early in `main`, and keeps the guard until it exits. Library crates never start it.

```rust
let scrubber = Arc::new(RedactorScrubber::new(redactor));
let config = TelemetryConfig::from_env("factory-worker", env!("CARGO_PKG_VERSION"), scrubber)?;
let _telemetry = factory_observability::telemetry::init(&config)?;
```

The three binaries do not write this themselves. `factory_composition::telemetry::config_for` builds the configuration from the redactor of the composition root, and `telemetry::init` installs it. The redactor is the same `Arc` that every adapter and stage handler receives.

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

For the first end-to-end run, the [runbook of first-run signals](runbook-first-run-signals.md) says which span, metric and log line to look at for a stuck lease, a stage over its deadline, a gate blocked by the environment, a job over budget and a redaction hit, and which of those signals no code records yet.

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

The crate depends on one workspace crate, `factory-domain`, which the dependency rules allow. It supplies the redactor behind the `Scrub` seam, the `JobId` type and the derived `Traceparent`. The crate does not use the `regex` crate itself; the redactor, which does, lives in `domain`. `tracing-opentelemetry` and `opentelemetry`, already dependencies, set the remote parent of the job stretch span.

## 12. Decided, and what is not done

### Decided (ADR 0013)

- **One redactor.** The factory has one `Redactor`, in `domain::redaction`. This crate implements the `Scrub` seam over it (`RedactorScrubber`), and the stopgap scrubber with the test that kept it equal to the policy was deleted. The scrubber is a required argument of `TelemetryConfig::new`. The composition root builds the redactor from the loaded policy and the registry of secret values and passes it to every binary through `factory_composition::telemetry::config_for`.
- **Peer crates write the names as literals.** The dependency rules forbid a dependency between two crates in the application and adapter ring, and a constant cannot name a field in a `tracing` macro. `workflow`, `runtime`, `sandbox` and the others write the same strings in their own `tracing` calls. The tables here are the reference. The repository-wide ST-07 scan in `xtask check-architecture` checks the literals against the tables, and `s1-observability-instrumentation` checks the spans they produce.
- **A job is one trace, found from its id.** No span is held open for a job. Each stretch of work opens a `factory.job` span whose remote parent is derived from the job id (section 3), and the engine writes the derived `traceparent` into each outbox event.

### Not done

- **Consumers do not continue the trace.** Consumers of outbox events do not yet continue the trace from `traceparent`, and there is no stitched job timeline in the dashboard. Both are Slice 2 work in ADR 0013. How a given backend draws a stretch whose parent was never exported has not been checked against a real Jaeger; the generated trace of the first end-to-end run is to be read once by hand.
- **Gap OBS-1 (fixed): a second URL with a password on one log line escaped the redactor.** The `url_with_credentials` pattern used to end only at white space or a slash, so on a JSON log line its match ran past the closing quote and, when the same URL stood twice on one line, ended inside the second URL, where the regex engine no longer reported it. The password and host classes of the pattern in the security policy now stop at quotes and at the delimiters of a JSON line. The test `a_url_with_a_password_twice_on_one_log_line_is_redacted` in `crates/observability/tests/canary.rs` is no longer ignored.
- **Confirmed gaps in the call sites.** `s1-observability-instrumentation` checked the spans, metrics and log fields that other packages write against this page and found ten gaps, OBS-2 to OBS-11. Each had a test that failed, marked as ignored with the gap number in the reason so that the build stayed green. The telemetry gap fix closed all ten: the tests are no longer ignored, and the entries below say how each was closed and what it leaves open. While checking OBS-4 it found one more, OBS-12, which stays open and keeps an ignored test. `cargo nextest run --workspace --run-ignored only` runs the ignored tests. A test in `crates/composition/tests/runbook_names.rs` fails when an entry says "(fixed)" and its test is still ignored, or the reverse. The gaps are:
  - OBS-2 (fixed): the engine opened no `factory.stage_run` span. `run_attempt` in `crates/workflow/src/engine/attempt.rs` now opens one for each attempt it runs, and the attempt span hangs from it (see section 3). The tests `a_stage_run_span_sits_between_the_job_and_the_attempt` in `crates/workflow/tests/trace_shape.rs` and `some_code_opens_the_stage_run_span` in `crates/composition/tests/span_openers.rs` are no longer ignored. The expected parent of the attempt changed in `trace_shape.rs` and in `one_trace_across_restarts.rs`, with a comment in each.
  - OBS-3 (fixed): no code opened a `factory.agent` span. The engine now hands each handler a runtime that wraps `AgentRuntime::run` in one (`crates/workflow`, `src/engine/agent_span.rs`; the same wrapper serves `execute` and the gate). The span hangs from the span that is current when the handler calls, which is the attempt or its gate. It carries the agent id, the model the router chose, the outcome (`succeeded`, `timed_out`, `cancelled` or `failed`), the token counts as signed integers and the cost in dollars as the adapter reported them. A failed run sets `error.type` to a fixed word for each variant of the closed error set (`timeout`, `provider_unavailable`, `budget_refused` and so on), and no text from the tool. The cost on this span is what the adapter reported; the broker's meter remains the source for `factory_spend_usd_total`. `factory.prompt_sha256` is not recorded yet. The test `some_code_opens_the_agent_span` in `crates/composition/tests/span_openers.rs` is no longer ignored, and `trace_shape.rs` tests the span.
  - OBS-4 (fixed): no code opened a `factory.tool_call` span. Both adapters in `crates/runtime` now open one for each tool call they read from the tool's event stream (`src/toolspan.rs`, called from `interpret` in `claude/mod.rs` and `codex/mod.rs`). A tool call is untrusted, so a span records no text from it. `factory.tool_name` is one of a fixed list of words chosen by the adapter: for Claude Code the built-in tools it grants (`Read`, `Glob`, `Grep`, `Edit`, `Write`, `Bash`, `Skill`), for Codex `shell` and `mcp`, and `unlisted` for any other name; the value is a `&'static str`, so a name from the stream cannot reach it. `factory.tool_args_sha256` is the SHA-256 of the arguments, 64 hex characters. `factory.outcome` is `succeeded`, `failed`, `denied` (the tool refused the call) or `cancelled` (the stream ends with no result for the call). The result, its output and its error text are never recorded. A run opens at most 256 of these spans. The adapter reads the stream after the tool has ended, so the span's duration is not the call's duration. The tests in `crates/runtime/tests/telemetry.rs` run both adapters over recorded and hostile streams. `some_code_opens_the_tool_call_span` in `crates/composition/tests/span_openers.rs` is no longer ignored. What the span still lacks is tracked as OBS-12.
  - OBS-5 (fixed): nothing recorded `factory_queue_depth`. `claim_next` (`crates/workflow`, `src/scheduler/claim.rs`) now sets the gauge on every call, zero included, to the number of ready stage runs its lookup found, as a signed integer with the label `queue` set to `ready_stage_runs`. The lookup returns at most `claim_batch` rows (8 by default, 1 in the engine the worker loop is written for), so the gauge is the depth up to that bound and not a true count. A true count needs a read-only method on the store port, which is outside this package and needs the architect. The test `the_queue_depth_gauge_is_recorded_when_work_is_claimed` in `crates/workflow/tests/metric_names.rs` is no longer ignored.
  - OBS-6 (fixed): nothing recorded `factory_stage_duration_seconds`. The engine now records it, with `factory_stage_runs_total`, when a decision ends a stage run (`crates/workflow`, `src/engine/ended.rs`, called from `gate.rs` and `failure.rs`). The time runs from the first start of the stage run, so it includes failed attempts, retry back-offs and waits for a person. The metrics are recorded when the decision commits, so a decision that loses a race counts nothing. The test `the_stage_duration_histogram_is_recorded_when_a_stage_run_ends` in `crates/workflow/tests/metric_names.rs` is no longer ignored.
  - OBS-7 (fixed): nothing recorded `factory_spend_usd_total`. The engine now adds what the broker metered for an attempt's token, in dollars as a double, right after it reads it (`record_spend` in `crates/workflow/src/engine/attempt.rs`). An attempt that failed or lost its lease is counted, because the money was spent; nothing is added for zero. The broker reports no provider, so the `provider` label carries the name of the runtime the router chose for the stage (`claude-code-cli`, `codex-cli`), a closed set from the routing policy. Until the broker reports a provider, read the label that way. The test `the_spend_counter_is_recorded_when_an_agent_spends` in `crates/workflow/tests/metric_names.rs` is no longer ignored.
  - OBS-8 (fixed): `factory_stage_runs_total` was recorded only for `passed`, so the error-rate query on this page returned zero. It is now recorded for every way a stage run ends: `passed`, `failed`, `blocked` and `rework_requested`. The outcome is the status the stage run holds after the decision, not a guess from the branch taken. A retry and a question to a person leave the run open and are not counted. Cancelled, skipped and superseded runs end in other code paths and are not counted yet. The test `a_failed_stage_run_is_counted_in_the_stage_run_total` in `crates/workflow/tests/metric_names.rs` is no longer ignored.
  - OBS-9 (fixed): three log fields held text chosen by a repository or a tool: `path` in `crates/sandbox/src/workspace/ingest.rs`, and `visible` and `allowed` in `crates/runtime/src/codex/mod.rs`. The audit now logs the number of rejected entries (`rejected`) and, for each, the reason kind and `path_sha256`, the first 12 hex characters of the SHA-256 of the path. The skill check logs `visible_count` and `allowed_count` and `visible_sha256` and `allowed_sha256`, digests of the sorted names joined by line feeds. The digest is the workspace's `Sha256Digest`, cut to 12 characters in each crate. The full paths stay in the report that `keep_report` keeps for the caller, and the names are not logged anywhere. The fields are on the reviewed list of `crates/composition/tests/telemetry_allowlist.rs`; the test `no_log_field_holds_text_chosen_by_a_repository_or_a_tool` is no longer ignored and now proves that the three old fields are gone, and `a_field_named_as_a_digest_is_filled_by_a_digest_helper` proves that each `*_sha256` field is filled by a digest.
  - OBS-10 (fixed): no metric counted redactions. The lead approved a counter, `factory_redactions_total`, with the single label `kind` (`redacted`, `truncated`, `dropped`); it is in the metrics table above, **added in the telemetry gap fix; architect confirmation pending**. It is fed from the guard's `GuardStats` at the place each count is raised (`crates/observability/src/guard.rs`), and only the kind reaches it. The label set is closed: the only source of the label is the `RedactionKind` enum, `record_redaction` takes nothing else, and the meter provider's view drops any other label key and caps the series. Scrubber failures count as `dropped`, and the log writer's redactions are not counted; the architect may want a fourth kind for the first. The test `a_redaction_is_counted_in_a_metric` in `crates/observability/tests/redaction_signal.rs` is no longer ignored, and the tests next to it show the metric equals the guard's counts and that no secret, pattern id or free text reaches a label.
  - OBS-11 (fixed): the attempt span did not record `factory.error_class`. It now declares the field and, when the attempt failed, records the failure class in its wire spelling (`TOOL_ERROR`, `TIMED_OUT` and so on), a closed set. An attempt that did not fail leaves the declared field empty, so `declared_only` checks on the attempt span ignore that one field (see `every_handler_has_a_span.rs`). The test `a_failed_attempt_span_records_the_failure_class` in `crates/workflow/tests/trace_shape.rs` is no longer ignored.
  - OBS-12: the `factory.tool_call` span lacks `factory.correlation_id` and `factory.job_id`, which the span table requires (`crates/runtime`, found while closing OBS-4). `AgentRunRequest` names the attempt and nothing else of the job, so the adapter cannot fill them. They are on the parent `factory.agent` span, and the two share a trace. Smallest change, for the software architect: add the correlation id and the job id to `AgentRunRequest` in `crates/ports` (a port change, outside the telemetry package), and have the adapters put them on the span. The test `a_tool_call_span_carries_every_attribute_the_page_requires` in `crates/runtime/tests/telemetry.rs` is ignored until then.
- **No OTLP logs.** Logs go to standard error. The policy names `otel_log_records` as a sink, and the pipeline would need the `opentelemetry-appender-tracing` crate, which is not on the allow list.
- **No alert rules or dashboards.** This page fixes the names and the data. Rules and dashboards come after the first end-to-end run shows what values the metrics take.
- **The sample is a sample.** The `emit_sample` example in the crate sends fake identifiers to a collector, with a redactor that has no pattern.
