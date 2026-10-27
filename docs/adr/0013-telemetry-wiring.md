# 0013: Keep telemetry names as literals and scan the repository, inject one redactor from the composition root, and trace a job by an id derived from the job

- Status: Accepted by the architect. The defaults are **pending human confirmation** and are item 14 of [ADR 0009](0009-operating-defaults-pending-confirmation.md).
- Date: 2026-10-27
- Deciders: software_architect. The names, tables and exporter belong to the observability specialist ([conventions](../observability/conventions.md)).
- Related: [ADR 0002](0002-workspace-layout-and-dependency-rule.md), [ADR 0004](0004-event-model.md), [conventions](../observability/conventions.md) sections 3, 8 and 12, negative tests ST-07 and NT-SEC-01

## Context and problem statement

The telemetry baseline (`crates/observability`) fixes the span names, the attribute allowlist, the metric table and a stopgap secret scrubber. Section 12 of the conventions page lists three things it does not settle. Each needs a decision before the engine and the composition roots are written, because they decide what those packages must do.

1. Peer crates (`workflow`, `runtime`, `sandbox`) cannot import `observability`, so they cannot use its name constants. Who checks that the names they write are the right ones?
2. There are two secret redactors: the stopgap in `observability` and the real `domain::redaction` of the package `s1-redaction`. Who connects the real one, and who deletes the stopgap?
3. A job lives for hours or days across restarts, and a span is exported only when it ends. How is a job one trace?

## What was checked

On 2026-10-27, in this repository.

- `docs/architecture/crate-dependency-rules.json`: `workflow`, `runtime` and `sandbox` list `tracing` and no workspace peer. Ring 2 crates may not depend on each other (DEP-02).
- `docs/observability/conventions.md` section 5 writes metric calls as `tracing::info!(monotonic_counter.factory_retries_total = 1u64, stage = "IMPLEMENTATION")`. A field name in a `tracing` macro is written as tokens in the call, so a constant cannot name it. This is the reading of the examples; the macro grammar was not compile-tested for this record.
- `crates/observability/src/redact.rs` holds `PolicyPatternScrubber`, and `TelemetryConfig::new` installs it by default. `with_scrubber` replaces it. A test keeps its pattern list equal to `policies/security.yaml`.
- `crates/observability/tests/st07.rs` checks only the names the observability crate defines or uses, and says the repository-wide scan does not exist.
- `crates/domain/src/values/text.rs` has `TraceId`, `SpanId` and `Traceparent` types with the W3C patterns. The event schema has an optional `traceparent`.

Not verified: how `tracing-opentelemetry` 0.34 sets a remote parent from a given trace id (I expect `OpenTelemetrySpanExt::set_parent` with a context that holds a remote span context), how Jaeger draws a span whose parent was never exported, and whether any backend dislikes a trace id with a time-ordered prefix. In a version 7 UUID the 56 rightmost bits are random, which fits the W3C advice on random trace ids as I remember it. That remains unchecked.

## Decision 1: names stay as literals in peer crates, and a repository-wide scan checks them

### Considered options

1. **Move the name constants to `domain`**, which every crate may import. This does not work for the fields, because a constant cannot name a field in a `tracing` macro. It would also put telemetry vocabulary in the domain crate.
2. **Let peers depend on `observability`.** Breaks the ring rule that ADR 0002 enforces and gives every crate the OpenTelemetry dependency tree.
3. **Literals in the peers, and a scan.**

### Outcome

Chosen: **option 3.** The `xtask` architecture check gains a repository-wide ST-07 scan. It reads every production source file in the workspace and collects:

- the name given to a span (`span!`, `info_span!` and its siblings, and `#[instrument(name = ...)]`),
- every field written with the `factory.` prefix and `error.type` in a `tracing` macro,
- every metric field (`monotonic_counter.`, `histogram.`, `gauge.`) and its labels.

It compares them with the tables on the conventions page, which the observability tests already parse (the tables sit between `<!-- table:... -->` markers). A name that is not in a table, a metric recorded with the wrong kind, and a label not listed for its metric each fail the check with the file and line. The crate-level test in `observability` stays. Its entry in the plan becomes "also" of the new check.

The scan is a guard rail like the other source scans. It reads text, so it misses a name built at run time. The trace tests of `s1-observability-instrumentation` cover that side, as the conventions page says.

## Decision 2: one redactor, connected by the composition root, and the stopgap deleted

### Outcome

- `s1-redaction` delivers `domain::redaction::Redactor`. Its done criteria do not change.
- A new package, `s1-telemetry-wiring` (role observability, depends on `s1-redaction`), changes only `crates/observability`. It implements the `Scrub` seam over the real redactor (the crate already depends on `domain`), deletes `PolicyPatternScrubber`, its rule list and the test that keeps it equal to the policy, and makes the scrubber a **required argument** of `TelemetryConfig::new`. There is no default. A binary that forgets to pass one does not compile, instead of starting with a weaker scrubber.
- `s1-apps-composition` builds the redactor from the loaded policy and the registry of the factory's own secret values, and passes it to `TelemetryConfig::new` in every binary. It depends on `s1-telemetry-wiring`.
- Until then the stopgap stays and is the default, as the conventions page says today. Nothing about it is promised beyond the patterns in the policy.
- The canary test NT-SEC-01 gets its telemetry sinks from this: a canary in a span attribute, a span event and a log line must not appear in the exporter output.

Two sources of the patterns would drift. The policy-sync test is the only thing that keeps them equal today, and deleting the stopgap removes the second copy.

## Decision 3: a job is one trace, found from its id, with no long-lived span

### Considered options

1. **One span held open for the whole job.** It is lost if the process dies, it is not exported until it ends, and it ties the span to one process. A job outlives any process.
2. **Span links between the pieces.** Needs stored span identifiers, so a column on the job row and a migration.
3. **A random trace context stored on the job at admission.** The same column and migration.
4. **A trace context derived from the job identifier.** Any process computes it. Nothing is stored.

### Outcome

Chosen: **option 4.**

- The **trace id** is the 32 lowercase hex characters of the job's UUID. The **root span id** is the first 16 hex characters of the SHA-256 of the text `factory.job` followed by the job id. The trace flags are `01`. A pure function in `domain` builds the `Traceparent` (row 21 of the domain checklist).
- **No span lasts for the whole job.** Each process that starts work on a job opens a `factory.job` span for that stretch of work: the API while it handles a command, the worker while it holds a claim. The span's remote parent is the derived context. Stage run, attempt, agent, tool call and gate spans hang from it as the conventions page describes. The derived root itself is never exported, so a backend shows the stretches as children of a missing parent inside one trace. How a given backend draws that is not verified.
- **The composition roots open the stretch.** `workflow` may only use `tracing`, so it cannot set a remote parent. The worker loop and the API handlers, which are in ring 3 and may use `observability`, create the stretch span with a helper in the `observability` crate and run the engine call inside it. Spans that `workflow` creates then take it as their parent.
- **Events carry the derived `traceparent`.** The engine writes it into each outbox event. It is computed from the job id with the domain function, so `workflow` needs no new dependency. It links an event to the job's trace. It does not name the exact span that caused the event, which `causation_id` already does at the event level.
- **A restart needs no restoration.** The next process computes the same trace id and opens a new stretch.

### What belongs to which slice

| Slice 1 | Slice 2 |
|---|---|
| The derived `traceparent` function in `domain` | Consumers of events continue the trace from `traceparent` |
| The stretch span helper in `observability`, used by the worker and the API | A stitched job timeline in the dashboard |
| The derived `traceparent` in every outbox event | Exact span linking through a `ports` trait, if the timeline needs it |
| A test that two engine instances working on one job produce one trace id | |

## Consequences

- Good: a search by job finds every span across restarts, with no schema change.
- Good: the name check covers the whole repository, and the gap in section 12 of the conventions page closes.
- Good: the redactor has one implementation, and a forgotten injection is a compile error.
- Bad: span causality across stretches is by trace and time, not by parent. A reader sees several `factory.job` spans in one trace.
- Bad: the scan is a text scan and has the limits of one.
- Bad: one more package, `s1-telemetry-wiring`, and a dependency from `s1-apps-composition` to it.
- Neutral: the trace id exposes the job id. It is already an attribute on every span.

## Confirmation

The ST-07 scan has a failing fixture for an unknown span name, an unknown field and a metric with the wrong kind. A test shows a canary secret removed from a span, a span event and a log line by the real redactor. A test shows two engine instances on one job with one trace id (`s1-observability-instrumentation`). The generated trace for the end-to-end run is read once by hand to see how the missing parent looks.
