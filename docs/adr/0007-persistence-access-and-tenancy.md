# 0007: Access PostgreSQL through Diesel with diesel-async, and scope every row and every call by tenant

- Status: Accepted. Revised on 2026-10-27 by [ADR 0012](0012-row-level-security-in-slice-1.md): row-level security moves into Slice 1, claims lock with `FOR NO KEY UPDATE`, and PostgreSQL 18 is the pinned version (see "Revision note").
- Date: 2026-10-27
- Deciders: software_architect (schema design belongs to the DBA)
- Related: [ADR 0001](0001-orchestration-engine.md), [ADR 0004](0004-event-model.md), [ADR 0008](0008-artifact-store-and-evidence-ledger.md), [ADR 0012](0012-row-level-security-in-slice-1.md)

## Context and problem statement

The master prompt names PostgreSQL with Diesel for transactional state (section 1), a tenant-aware data model and authorization for several organizations, repositories and branches, and forward- and backward-compatible migrations (section 13). The DBA designs the schema while engineers write the storage adapter against ports. They need shared rules first: the access library, how tenancy is expressed, where transactions begin and end, and how concurrent writers are kept apart.

## Revision note

Three statements of the first version changed after the DBA's schema work and the architect's measurements on 2026-10-27. [ADR 0012](0012-row-level-security-in-slice-1.md) carries the reasons and the evidence.

1. Row-level security is in Slice 1, not Slice 4 (rule 4 and the second "Bad" consequence).
2. Claiming work uses `FOR NO KEY UPDATE SKIP LOCKED` (rule 6). Measured: it does not block ledger, audit or outbox inserts, and `FOR UPDATE` does.
3. The PostgreSQL major version is 18, and it is pinned in Compose and CI (the last "Neutral" consequence).

The rest of the record is unchanged.

## What we checked

On 2026-10-27: `diesel` 2.3.14 and `diesel-async` 0.9.2 on crates.io (the latter last updated 2026-06-19 and not yet 1.0); the `diesel` command line tool 2.3.11 is installed; `psql` 18.6 is installed; Docker has a `postgres:17-alpine` image locally and a `postgres:18` manifest exists on Docker Hub; `deadpool` 0.13.1 (2026-08-26) and `bb8` 0.9.1 (2025-11-24) are candidate pools. No query was run against a server. We did not test `diesel-async` with any of our patterns (`FOR UPDATE SKIP LOCKED`, `jsonb`, transactions across `await` points).

## Considered options

1. **Diesel with `diesel-async`.** Async end to end on Tokio. Pre-1.0 companion crate.
2. **Synchronous Diesel with a pool and `spawn_blocking`.** The most established path. Every call crosses a blocking thread, and the pool size and the Tokio blocking pool become coupled.
3. **`sqlx`.** Async-native with compile-time checked queries. The prompt specifies Diesel, and the `sqlx` command line tool being installed here is not a reason to override that.

## Decision outcome

Chosen: **option 1**. The choice is confined to the `storage` crate, so reversing it means rewriting one adapter and no use case.

### Rules for the DBA and the storage adapter

1. **Migrations** live in `migrations/` at the repository root, owned by the DBA, run by `diesel migration run` in development and CI and by a separate deploy step in production. Applications never migrate themselves. They check the schema version at start-up and refuse to become ready if it is behind. Schema changes follow expand, migrate, contract, so version N and N+1 of the code can run on the same schema.
2. **Generated schema** (`diesel print-schema`) is committed. CI creates a fresh database, runs the migrations, prints the schema and fails on any difference.
3. **State values are checked by the database.** Every status column rejects unknown values, built from the state lists in [`state-machine.json`](../architecture/state-machine.json). The mechanism (text with `CHECK`, or enum types) is the DBA's choice. A test inserts an unknown status and expects a rejection.
4. **Tenancy.**
   - Every tenant-owned table has `tenant_id uuid NOT NULL`.
   - Foreign keys between tenant-owned tables include `tenant_id` on both sides, so a row cannot reference another tenant's parent. Unique constraints include `tenant_id`.
   - Every repository method takes a `TenantScope` value. There is no method without one, so a query that forgets the tenant does not compile.
   - Row-level security is **on in Slice 1**, as ADR 0012 designs it: `FORCE ROW LEVEL SECURITY`, a transaction-local tenant setting made by `Store::begin`, and a separate role and pool for the system scope. The keys, the scope type and the isolation tests stay, because they catch faults that the database policy does not (a wrong tenant on a write).
5. **One transaction per decision.** `Store::begin(scope)` returns a `Tx`. The status change, ledger entries and outbox rows for one transition are written in that `Tx` and committed together (invariant INV-03). No `await` on anything other than the database happens while a `Tx` is open.
6. **Concurrency.** Mutable aggregate rows carry `version bigint`. Updates are `WHERE id = $1 AND version = $2`. Zero rows updated is `StoreError::Conflict`. Default isolation is READ COMMITTED. Claiming work uses `FOR NO KEY UPDATE SKIP LOCKED`, because `FOR UPDATE` would block the ledger, audit and outbox inserts that take a `KEY SHARE` lock on the same row. The DBA confirms that no path needs SERIALIZABLE.
7. **Identifiers and time.** Identifiers are UUID version 7 made by the `IdGenerator` port and stored as `uuid`. Timestamps are `timestamptz`. Lease expiry and deadlines are compared with the **database clock** inside the claim and sweep queries, exposed as `Tx::database_time()`, so skew between worker hosts cannot extend or shorten a lease. The `Clock` port serves everything else, and the in-memory store in `testkit` returns the fake clock for `database_time()`.
8. **Untrusted text is stored apart.** The original request text lives in its own table with a content hash. Everything else refers to the normalized request.
9. **No secrets in the database.** Credentials are references to a secret store (`security` defines it). Logs and prompts are artifacts (ADR 0008), not columns.

### Required tests

- A tenant isolation test for every repository method: with rows for tenants A and B, a call scoped to A never returns, updates or deletes a B row.
- The atomicity tests from ADR 0004 and invariant INV-03.
- A claim test with two concurrent claimers on one ready row: exactly one wins.
- A migration test: up, down, up on an empty database, and a data-preserving upgrade test for each later migration.

### Consequences

- Good: async from the socket up, no blocking-pool coupling, and the choice is local to `storage`.
- Good: tenant mistakes become type errors and key violations rather than review findings.
- Bad: `diesel-async` is pre-1.0 and younger than `diesel`. If it fails a requirement we hit in Slice 1, we fall back to option 2 inside `storage`.
- Bad: row-level security needs two database roles, two connection pools in the worker, and one more statement per transaction (ADR 0012).
- Bad: schema generation and `diesel` tooling add a CI step and a pinned CLI version.
- Neutral: the PostgreSQL major version is 18, pinned in Compose and CI. The DBA tested 18.6 and 16.15. Version 17 was not run.

## Pros and cons of the options

**`diesel-async`**: Tokio-native, fits the stack. Smaller community and fewer features than sync Diesel.

**Sync Diesel with `spawn_blocking`**: the most proven. Awkward with transactions that span async code and costs threads.

**`sqlx`**: pleasant to use, checks SQL at compile time against a live database. Contradicts the stated requirement and adds a second query style if anyone mixes the two.
