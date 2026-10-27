# 0004: Publish domain events through a transactional outbox to NATS JetStream, at least once, with idempotent consumers

- Status: Accepted Revised again on 2026-10-27 by ADR 0014 (see "Revision note (ADR 0014)").
- Date: 2026-10-27
- Deciders: software_architect
- Related: [ADR 0001](0001-orchestration-engine.md), [state machines](../architecture/state-machine.md), [`domain-event` schema](../../schemas/domain-event.schema.json)

## Revision note (ADR 0014)

Revised on 2026-10-27 by [ADR 0014](0014-ports-v1-1-claim-protocol-and-port-revision.md): the outbox is a notification record and not a read model. The engine lists rows instead of reading stage runs and attempts out of event payloads, and no creation event is added. The `ChangeHost` documentation said a comment is posted at most once per key; it is at least once with a marker that reduces duplicates, as this record already said.

## Context and problem statement

State changes must reach other components (the dashboard, notifiers, evaluation) without losing events when a process crashes between "write the state" and "tell the world". The master prompt (section 13) asks for a transactional outbox, NATS JetStream for integration events, consumer idempotency keys, monotonic transitions, and documented at-least-once delivery. It says not to pretend exactly-once side effects exist. Diagnostic logs must stay separate from domain events.

## What we checked

- `nats-server` 2.15.1 is installed. Its help lists `-js` (enable JetStream) and `-sd` (store directory). We did not start a server in this session.
- The [NATS streams documentation](https://docs.nats.io/nats-concepts/jetstream/streams), read on 2026-10-27, says that for two minutes after a message is stored the server rejects a second message carrying the same `Nats-Msg-Id` header, and lists "Duplicate Window: 2m0s" as the default.
- A documentation search the same day summarized NATS as describing exactly-once as de-duplication plus double acknowledgement. We did not read that statement on a page, and this design does not rely on it.
- `async-nats` 0.51.0 was updated on crates.io on 2026-10-26.

Not verified: any JetStream behavior on this machine or on version 2.15.1, consumer settings such as acknowledgement wait and maximum deliveries, dead-letter handling.

## Considered options

1. **Publish to NATS directly after the database commit.** A crash between commit and publish loses the event. Publishing before the commit can announce a change that never happened.
2. **Transactional outbox with a relay.** The event is a row written in the same transaction as the state change. A relay publishes rows and marks them sent.
3. **Change data capture from the PostgreSQL log** (logical replication). No relay code, but a replication slot, a decoding component and an operational dependency that the outbox does not need.
4. **PostgreSQL `LISTEN/NOTIFY` as the bus, no NATS.** Not durable across disconnects and limited in payload size. It also drops the integration point the prompt asks for.

## Decision outcome

Chosen: **option 2**.

### Write side (Slice 1)

- Every transition writes its domain event to an `outbox` table in the same transaction as the status change and the ledger entries. If any part fails, none of it exists.
- The envelope is [`schemas/domain-event.schema.json`](../../schemas/domain-event.schema.json). Event types are the `emits` values in [`state-machine.json`](../architecture/state-machine.json). Attempt heartbeats are not events.
- Each event carries `transition_id` (the machine-readable reason), `correlation_id` (shared by everything in a job), `causation_id`, `aggregate.version` and an optional W3C `traceparent`.
- Payloads carry identifiers and hashes, never prompts, source code, model output or secrets. Large content lives in the artifact store.
- Slice 1 has **no relay and no NATS dependency**. Nothing consumes events yet. The job timeline reads the `outbox` and the evidence ledger. Writing the rows from the start means Slice 2 retrofits nothing.

### Publish side (Slice 2, `events` crate)

- The relay selects unpublished rows with `FOR UPDATE SKIP LOCKED`, publishes each with `Nats-Msg-Id` set to `event_id`, and sets `published_at` after the acknowledgement.
- A crash between publish and marking republishes the row. JetStream drops the duplicate if it falls inside the stream's duplicate window. Outside the window a duplicate is delivered, so consumers must be idempotent either way.
- Subjects follow `factory.v1.<tenant_id>.<aggregate>.<event>`, so NATS permissions can be scoped per tenant. Stream retention is time-limited. The `outbox` table, not JetStream, is the long-term record.
- Delivery is **at least once end to end**. Ordering is per aggregate only. The global row sequence can have gaps and out-of-order commits under concurrency, so consumers use `aggregate.version` to detect gaps and reordering and never rely on arrival order.

### Consumer side (Slice 2)

- Durable pull consumers with explicit acknowledgement and a bounded number of deliveries. Events that exceed it go to a dead-letter path and raise an alert.
- The idempotency key is `event_id`. A consumer owns an `inbox` table with a unique `(consumer, event_id)`.
- Effects inside PostgreSQL commit together with the inbox row, which gives exactly-once effect inside the database.
- Effects outside the database, such as a GitHub comment, are at least once. The consumer derives a stable key from `event_id` and the effect name, records it in an `external_effect` table, and embeds it in the artifact where the target allows (a hidden marker in a comment) so a retry can find its earlier work. This reduces duplicates. It does not make them impossible, and no document may claim otherwise.

### Consequences

- Good: no lost events and no events for rolled-back changes; the audit trail comes from the same rows; the relay is small and easy to test with a killed process.
- Good: the Slice 1 stack stays free of a message broker.
- Bad: the relay is one more component to run and monitor. Its lag becomes a metric and an alert.
- Bad: consumers carry the idempotency burden, and the external-effect case is only best effort.
- Bad: the outbox grows. The DBA must define retention and partitioning before Slice 2 load tests.
- Neutral: JetStream's duplicate window is a short-term safety net and must not be treated as the idempotency mechanism.

## Pros and cons of the options

**Direct publish**: simplest code, silently loses or invents events on failure. Rejected on correctness.

**Outbox**: standard, testable, needs a relay and idempotent consumers.

**Change data capture**: strong ordering and no relay code, but a heavier operational footprint and tighter coupling to the table layout.

**`LISTEN/NOTIFY`**: no extra service, but not durable and not what the prompt asks for.

## Confirmation

- Slice 1: a database test that makes the transaction fail after the outbox insert and sees no row, and one that fails before it and sees no state change.
- Slice 2: kill the relay between publish and marking and prove consumers still apply each effect once; publish the same `event_id` twice outside the duplicate window and prove the inbox absorbs it; deliver events out of order and prove the version check catches it.
