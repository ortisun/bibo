# Observability conventions

- Status: Slice 0 baseline. The names and tables below are checked by tests in `crates/observability`. No factory service records them yet; the call sites arrive in Slice 1.
- Owner: observability. Reviewer: software architect.
- Package: `s0-telemetry-baseline`. The Slice 1 package `s1-observability-instrumentation` verifies the call sites against this page.
- Related: [ADR 0004](../adr/0004-event-model.md) for domain events, [secrets and credentials](../security/secrets-and-credentials.md) for redaction, [`policies/security.yaml`](../../policies/security.yaml) for the secret patterns.

## 1. What this page fixes

The factory exposes two kinds of telemetry: traces, and metrics that VictoriaMetrics can store. It also writes diagnostic logs. This page fixes the names, the types and the rules for all three, so that a person reading a trace and a dashboard sees the same words.

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
| `factory.cost_usd` | double | unbounded | `factory.agent` | Cost in US dollars the broker metered for this invocation. |
| `error.type` | string | bounded | `factory.job`, `factory.stage_run`, `factory.attempt`, `factory.agent`, `factory.tool_call`, `factory.gate` | The standard error.type key. A short error kind, never a message. |
<!-- /table:attributes -->

### Outcome values

`factory.outcome` and the metric label `outcome` take one of these values, each the lower case form of a state in the state machine file or of a gate outcome in the gate report schema: `passed`, `failed`, `blocked`, `not_applicable`, `succeeded`, `timed_out`, `lease_lost`, `cancelled`, `denied` and `rework_requested`. `denied` is for a tool call that policy refused.
