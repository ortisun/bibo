# 0001: Orchestrate with a narrow PostgreSQL durable state machine; Temporal is not integrated

- Status: Accepted (architect decision; awaiting human confirmation, see open questions in the Slice 0 report). The claim query was corrected on 2026-10-27 from `FOR UPDATE SKIP LOCKED` to `FOR NO KEY UPDATE SKIP LOCKED`, which gives the same exclusion between claimers and does not block evidence writers ([ADR 0012](0012-row-level-security-in-slice-1.md)).
- Date: 2026-10-27
- Deciders: software_architect
- Related: [state machines](../architecture/state-machine.md), [ADR 0004](0004-event-model.md), [ADR 0007](0007-persistence-access-and-tenancy.md)

## Context and problem statement

A job moves through about a dozen stages. A stage runs for seconds to tens of minutes, may call an agent, and may wait days for a human. The orchestrator has to survive crashes, retry with limits, honor timeouts and cancellation, and never advance because an agent claimed success.

The master prompt makes PostgreSQL the source of truth for job, stage, attempt, lease, approval and evidence state (sections 1 and 13). It asks us to evaluate Temporal, including how mature its Rust SDK is, or to build a narrow PostgreSQL-backed durable state machine, and never to claim Temporal is integrated when it is not.

Which engine runs the pipeline?

## What we found about Temporal's Rust SDK

Checked on 2026-10-27. The premise "the Rust SDK is too immature" no longer holds, so this decision rests on other grounds.

| Fact | Source | Date |
|---|---|---|
| Rust SDK announced as public preview | [Temporal changelog entry](https://temporal.io/changelog/rust-sdk-public-preview) | 2026-05-07 |
| Rust SDK announced as generally available | [Temporal changelog](https://temporal.io/changelog), entry "Temporal's Rust SDK is now Generally Available" | 2026-09-04 |
| Blog post announcing general availability | [temporal.io blog](https://temporal.io/blog/build-durable-applications-rust-temporal-rust-sdk-now-generally-available) | 2026-09-23 (the changelog and the blog disagree by 19 days; crates.io and GitHub agree with 09-04) |
| `temporalio-sdk` 1.0.0 and 1.1.0 published, not yanked | [crates.io API](https://crates.io/api/v1/crates/temporalio-sdk) | 2026-09-04 and 2026-10-06 |
| GitHub releases v1.0.0 and v1.1.0, neither marked prerelease; MIT license; last push 2026-10-26 | GitHub API for `temporalio/sdk-rust` | 2026-09-04, 2026-10-06 |
| Developer docs list "Rust (v1.1.0)" | [docs.temporal.io/develop](https://docs.temporal.io/develop) | read 2026-10-27 |
| `temporalio-sdk-core`, the crate under the SDK, is still 0.10.0 | crates.io API | 2026-10-06 |
| Minimum Rust version 1.92.0 | crates.io metadata for 1.1.0 | 2026-10-06 |
| Signals, queries, updates, timers, retries, child workflows, continue-as-new, patching, replay testing | GA blog post | 2026-09-23 |
| The determinism detector "cannot catch every change in polling order or synchronous calls such as `SystemTime::now()`" | GA blog post | 2026-09-23 |
| Workers need a Temporal server, either Temporal Cloud or self-hosted | GA blog post | 2026-09-23 |

Local checks on this machine:

- A scratch crate depending on `temporalio-sdk =1.1.0` passed `cargo check` on rustc 1.98.0 in 92 seconds from a cold cache. `cargo tree` shows 321 unique crates for that one dependency. The probe lives outside the repository.
- The `temporal` command line tool is not installed. The server image `temporalio/temporal:latest` exists on Docker Hub (`docker manifest inspect` succeeded). We did not start it.

Not verified: running a workflow against a server, activity heartbeats for long agent runs, patching a long-lived workflow whose definition changes every week, the memory and operational footprint of a self-hosted server, and what general availability means for a 1.x SDK on a 0.x core crate.

## Decision drivers

1. **One source of truth.** The prompt wants job, stage, attempt, lease, approval and evidence state in PostgreSQL, tenant-scoped, with a transactional outbox. Temporal keeps its own event history. We would have two stores to reconcile.
2. **Time to the first real end-to-end run.** Slice 1 should need PostgreSQL and Docker, nothing more.
3. **Rules we own.** The transition rules are pure functions in `domain` whatever runs them. They need no engine.
4. **Reversibility.** The choice must be cheap to change if it turns out wrong.
5. **Slice 2 effort.** Leases, retries, timers, cancellation and crash recovery are the work Temporal would give us. This is the real argument for it.
6. **Track record.** The Rust SDK has been generally available for less than two months.

## Considered options

1. **Temporal now.** Add the Rust SDK and a self-hosted Temporal server. Model the pipeline as a workflow and stage handlers as activities. Project state into PostgreSQL for queries, audit and the dashboard.
2. **A narrow PostgreSQL durable state machine.** Rows hold the state. Transitions are pure functions. A claim query with `FOR NO KEY UPDATE SKIP LOCKED` hands out work. Leases carry an epoch for fencing. A sweeper handles deadlines and back-off. A small `Engine` boundary keeps the choice replaceable.

Not evaluated: Restate, DBOS and Rust job-queue crates. They are outside this decision. See the triggers below.

## Decision outcome

Chosen: **option 2**.

**Temporal is not integrated.** No Temporal crate is in the workspace, no Temporal server is in the Compose file, and no document may say the factory runs on Temporal.

The main reasons are drivers 1 to 4. A second durable store for orchestration state splits the source of truth the prompt asks for. The workload is a handful of long-running jobs per tenant, not thousands of workflows per second, so PostgreSQL polling is more than enough. The domain state we would need in PostgreSQL anyway (attempts, approvals, evidence, leases) is most of what a durable engine tracks. The engine boundary keeps the reversal cost low.

### What "narrow" means

The engine does these things and nothing else:

- Apply transitions from [`state-machine.json`](../architecture/state-machine.json) in one transaction with compare-and-swap on a version column.
- Claim ready stage runs with `SELECT ... FOR NO KEY UPDATE SKIP LOCKED`, create the attempt, and increment the lease epoch.
- Reject any worker write whose lease epoch is older than the stored one.
- Move expired deadlines, leases and retry back-offs forward on a sweeper tick. Timers are columns (`not_before`, `deadline_at`, `lease_expires_at`), never in-memory timers.
- Persist the ledger entries and outbox events that justify each transition in the same transaction.

It does not provide a workflow definition language, user-defined workflows, event-sourced replay of worker code, or any determinism requirement on stage handlers. The pipeline is a versioned table in code.

### The seam

`StageHandler::run(ctx) -> StageOutcome` contains no engine type. A Temporal adapter would replace the claim loop, the lease handling, the retry and timer logic and the sweeper. It would keep the transition functions, the stage handlers, the PostgreSQL schema, the ledger and the outbox. The stage handlers could run as Temporal activities unchanged.

### Consequences

- Good: one transactional source of truth; the state machine is a pure, fast-to-test function; Slice 1 needs only PostgreSQL; the Compose stack stays small.
- Bad: we own the correctness of lease fencing, deadline sweeping, back-off, cancellation propagation and crash recovery. Slice 2 exists to prove them with fault-injection tests, and until it is green the durability claim is unproven.
- Bad: we build a dashboard timeline ourselves. Temporal's UI would have come free. The dashboard is Slice 4, and the ledger already holds the data.
- Bad: there is a real risk of slowly rebuilding a worse Temporal. The scope fence above and the triggers below are the defense.
- Neutral: polling adds a delay of up to one sweep interval, which is irrelevant for stages that take minutes.

## Revisit triggers

Write a superseding ADR, and run a one-day spike first, if any of these happens:

1. The Slice 2 crash-recovery and fault-injection suite is not green after the effort agreed at Slice 2 planning, or fails the same class of test twice.
2. Sustained load makes claim queries or the sweeper a measurable share of database time (measure during Slice 2 before deciding anything).
3. A requirement appears for durable timers or signals at a scale or duration PostgreSQL polling handles badly.
4. The pipeline stops being a fixed table and becomes user-defined workflows, so we would be writing a workflow language. Dynamic task graphs inside a stage (Slice 3) do not count.
5. A customer requires Temporal Cloud.

## Pros and cons of the options

**Temporal now**

- Good: timers, retries, heartbeats, cancellation and replay are tested features we would not write; a mature UI; first-party Rust SDK, MIT licensed.
- Bad: a second durable store and a projection to keep consistent; a new server to run, secure and upgrade; 321 crates in the dependency tree; workflow code under determinism rules while the pipeline still changes weekly; our own cost of learning patching; a short GA track record; a Temporal server we have not run.

**Narrow PostgreSQL state machine**

- Good: see the consequences above.
- Bad: see the consequences above.

## Confirmation

- Slice 0: the conformance test between `state-machine.json` and the domain transition functions.
- Slice 1: an end-to-end run that restarts the worker between stages and finishes.
- Slice 2: the fault-injection suite (crash during attempt, crash during gating, duplicate claim, zombie worker, clock skew on lease expiry) is the real test of this decision.
