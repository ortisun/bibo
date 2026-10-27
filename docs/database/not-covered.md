# What the database baseline does not cover

- Status: baseline for Slice 0. This list is part of the deliverable, so a reader does not mistake the tests for more than they prove.
- Form: reference.

## In short

1. Row-level security is not enabled, and two documents disagree about whether it must be.
2. Nothing is ever deleted, and there is no retention design.
3. The audit anchor, the hourly verifier and the Rust chain verifier do not exist.
4. Nothing was measured under load, and PostgreSQL 17 was not run.
5. No Rust code touches the database yet.
6. A forgotten tenant filter in hand-written SQL, a superuser rewrite and a deleted audit tail all get past the database.
7. Several limits are my sanity bounds, not policy figures.

The tables below give the detail.

## Decided later, on purpose

| Not covered | Where it is decided | Why it matters |
|---|---|---|
| **Row-level security.** The baseline isolates tenants with keys, scoped queries and tests. `policies/security.yaml` says RLS is required. ADR 0007 defers it. | [tenancy.md](tenancy.md). Needs a person to reconcile the two documents, then an ADR before the second tenant. | A hand-written query that forgets `AND tenant_id = $1` is not caught by the database. |
| **Retention and deletion.** Nothing deletes anything. The application role has no `DELETE`. `webhook_deliveries` should be trimmed at 30 days, the outbox needs a retention rule (ADR 0004), and `jobs` can never be deleted while ledger entries exist, because the ledger is append-only and points at them. | A maintenance role and a retention design, with `s1-database-review`. Archiving or redacting a job, rather than deleting it, may be the answer. | Storage grows without limit. A request for deletion of personal data has no path yet. |
| **Partitioning** of the outbox, the audit log and the ledger. | Before the Slice 2 load tests (ADR 0004). | The tables are not partitioned and the audit chain is per tenant, which partitioning by tenant would fit. |
| **Other database roles.** There is one role, `factory_app`. A relay with only the outbox grants, a maintenance role, a read-only role for the dashboard and a role for the verification job would each hold less. | With the services that need them. | One role for everything is more power than the relay or the dashboard need. |

## Not built, but named in the design

| Not covered | Note |
|---|---|
| **The external anchor** for the audit chain head and the hourly verification job (`policies/security.yaml`, `audit`). | The chains are tamper-evident only to someone who holds an earlier head. See [ledger-and-audit.md](ledger-and-audit.md). |
| **The Rust chain verifier**, with RFC 8785 canonical form and JSON Schema checks. | The database checks the hash and the columns, not the canonical form or the schema. |
| **`external_effect` table** for effects outside the database (ADR 0004). | Slice 2, with the consumers. |
| **A general command idempotency table** for repeated human or worker commands (state-machine ground rule 7). | Jobs have an idempotency key, deliveries a unique id, events a unique version, inbox rows a key. A repeated approve or cancel command is covered by the unique index on approvals and by the state machine, but there is no table of seen command keys. The engine package should say whether it needs one. |
| **Budgets, quotas and cost counters.** | The schema has `max_attempts` per stage run and nothing for tokens, spend, concurrency or job quotas. They live in the broker and the policy engine for now. |
| **Job tokens of the model broker.** | The broker stores its own hash, binding and counters (`secrets-and-credentials.md`, section 4.2). `api_tokens` is not that table. |
| **Stage contracts, gate reports, review verdicts, specifications and plans as tables.** | They are artifacts named by hash. The database stores the hash and the metadata. Their schemas are validated by the code that writes them. |
| **The named allowlist** that gives a person authority. | Deliberately absent. Policy says it is read from protected configuration and never from the database. |
| **Backups, point-in-time recovery, replication, connection pooling, TLS, encryption at rest, `pg_audit`.** | `sre` items. The suite tests none of them. |

## Not proven by these tests

| Not covered | Note |
|---|---|
| **Behaviour under real load.** | The plans are on 10,000 rows on one laptop. There is no timing, no contention beyond four to fifty sessions, no bloat measurement and no check of `autovacuum` on the hot tables. `fillfactor` is at its default. |
| **Isolation levels other than `READ COMMITTED`**, replicas and failover. | The audit chain's advisory lock reasoning for `REPEATABLE READ` is untested. |
| **PostgreSQL 17.** | 16.15 and 18.6 passed. 17 was not run. |
| **The Rust code.** | `schema.rs` is generated and committed but not compiled yet: the `storage` crate has no Diesel dependency until `s1-storage-postgres`. No Rust test touches the database. |
| **Upgrade from an earlier schema.** | There is none. Each later migration needs a data-preserving test (ADR 0007). |
| **Tenant scoping in the Rust code.** | The tests prove the keys. They cannot prove that every repository call passes the right tenant. |
| **Business rules above the schema.** | Transition guards, gate decisions, pipeline order (INV-06, INV-11), rework counts, who may do what. These are in the domain and the engine. |
| **Whether artifact bytes match their hash.** | The artifact store checks that on read. |

## Known weak points in what is covered

| Weak point | Detail |
|---|---|
| **Only stage runs and attempts are frozen once terminal.** | `state-machine.json` asks for it only for stage runs (INV-04). A terminal job or task node cannot change status, because no transition leaves a terminal state, but its other columns (for example `policy_hash`) can still be edited by the application role. Freezing them is a small trigger if the architect wants it. |
| **A superuser can rewrite everything.** | The chains show partial tampering. A consistent rewrite from some point forward passes both verifiers. |
| **Deleting the end of the audit chain is not found** by `audit_verify_chain`. | A test states this limit. Only the anchor catches it. |
| **The owner role can `DROP TABLE`.** | Operational control only. |
| **The application role can create temporary tables.** | `TEMPORARY` on a database goes to `PUBLIC` by default. The trigger functions qualify every table with `public.` and pin `search_path`, so a temporary table cannot shadow what they read. Revoking `TEMPORARY` from `PUBLIC` and granting it back to the roles that need it is a hardening step for the deployment. |
| **Audit writes serialize per tenant.** | Fine at expected volume. If one job produced audit events at a high rate, the advisory lock would show up as latency. Writing audit events last in a transaction limits it. |
| **The composite keys and triggers add write cost.** | Every ledger, outbox and audit insert checks several keys, and `jobs` has two indexes that start with `(tenant_id, id)`. Not measured. |
| **`UNIQUE (tenant_id, body_sha256)` on deliveries** rests on an assumption about GitHub payloads. | See [constraints-and-indexes.md](constraints-and-indexes.md). |
| **Fixed limits** (a one-hour lease bound, a 16 KiB outbox payload, 1 MiB request text, 20 attempts per run) are my sanity bounds. | The policy gives no figure. Change them by migration. |
