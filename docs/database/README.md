# Database

PostgreSQL is the source of truth for the factory's jobs, stage runs, attempts, leases, evidence, approvals and audit trail. This directory documents the first schema, how to run its migrations, and what its tests prove.

- Status: the Slice 0 baseline (`s0-database-baseline`) plus row-level security and the revised state machine (`s1-database-tenancy-and-state-sync`, [ADR 0012](../adr/0012-row-level-security-in-slice-1.md) and [ADR 0010](../adr/0010-failure-escalation-routing-and-invalidation.md)). Not yet reviewed by the software architect or the security specialist.
- Verified: see the table of runs in [running.md](running.md). Fourteen migrations applied and reverted with Diesel 2.3.11, and 679 checks in fifteen suites passed on PostgreSQL 18.6 (local cluster and Docker) and 16.15 (Docker).

## Where to start

| You want to | Read |
|---|---|
| Run the migrations or the tests | [running.md](running.md) |
| See the tables and how they relate | [data-model.md](data-model.md) |
| Know why a constraint or index exists | [constraints-and-indexes.md](constraints-and-indexes.md) |
| Understand how tenants are kept apart (keys and row-level security), the roles, and what is left open | [tenancy.md](tenancy.md) |
| Understand the evidence ledger and the audit log, and how to verify them | [ledger-and-audit.md](ledger-and-audit.md) |
| Write the storage crate against this schema | [for-the-storage-crate.md](for-the-storage-crate.md) |
| Change the schema safely later | [migration-safety.md](migration-safety.md) |
| See the query plans on 10,000 and 100,000 rows, with row-level security on | [query-plans.md](query-plans.md) |
| Know what this work does not cover | [not-covered.md](not-covered.md) |

## What is in the repository

| Path | What it is |
|---|---|
| [`migrations/`](../../migrations/) | Fourteen Diesel migrations, each with `up.sql` and `down.sql`. The last five are new in the second package: the supersede edge for skipped stage runs, then the four row-level security parts (roles, tenant isolation, system scope, lookup functions). |
| [`crates/storage/diesel.toml`](../../crates/storage/diesel.toml) | Diesel configuration: migrations directory and the generated schema path. |
| [`crates/storage/src/schema.rs`](../../crates/storage/src/schema.rs) | The schema as `diesel print-schema` writes it. Generated, never edited by hand. |
| [`scripts/db-test.sh`](../../scripts/db-test.sh) | Builds a throwaway database, migrates it and runs the suites. |
| [`tests/`](tests/) | The SQL for each suite, the test helpers, two catalog queries, and `role_readiness.sql`, the start-up check of a pool's role. |
| [`tools/`](tools/) | `state_machine_sql.py` (reference rows and expected values from `state-machine.json`) and `verify_audit_chain.py` (rebuilds an audit chain outside PostgreSQL). |

The SQL tests live under `docs/database/tests/` because the work package owns `docs/database/**` and does not own a separate tests directory. That is a placement the architect may want to change.

## What the schema enforces, in one paragraph

Every tenant-owned table carries the tenant in its primary key and in every foreign key to another tenant-owned table, so a row cannot point at another tenant's row, and row-level security shows a session only the rows of the tenant named by the transaction-local setting `factory.tenant_id` (no setting, no rows, no error). The engine's cross-tenant loops use a separate role that can find work and cannot change it, and two narrow functions answer the questions that come before a tenant is known. Status columns accept only the values in `state-machine.json`, and a trigger accepts only the moves in it. A terminal stage run cannot be edited except to become superseded, which a passed or a skipped run may. An attempt holds the lease epoch of its stage run, only one attempt per run can be live, and a finished attempt keeps its result. The evidence ledger and the audit log cannot be updated, deleted or truncated by any role, and each row names its predecessor by hash. An outbox event names a real transition and a real aggregate, and cannot repeat for one aggregate version. An approval is bound to the commit and the evidence the human saw, and only a human principal can make one. The application role has the grants listed in one migration and no others.

## Decisions that need a person

These are the points I could not settle alone. Details are in the pages linked.

1. **ADR 0012 is pending confirmation** (ADR 0009 item 13). This build implements it. Where it deviates or is silent, [tenancy.md](tenancy.md) lists the choices: the system scope finds work and does not write it, `resolve_installation` takes the GitHub repository id too, a disabled tenant stops its tokens, `tenants` has a policy, and the receiver needs a platform scope in the ports.
2. **The ledger hash formula** reads "the previous entry's hash text" as the string with its `sha256:` prefix. See [ledger-and-audit.md](ledger-and-audit.md).
3. **`UNIQUE (tenant_id, body_sha256)` on webhook deliveries**, which assumes two legitimate deliveries never carry identical bytes. See [constraints-and-indexes.md](constraints-and-indexes.md).
4. **The platform tenant** for audit events that belong to no tenant. See [tenancy.md](tenancy.md).
5. **Claims lock with `FOR NO KEY UPDATE`** where the first version of ADR 0007 said `FOR UPDATE`. The ADR now says it too. Measured in the `lease` suite. See [for-the-storage-crate.md](for-the-storage-crate.md).
6. **PostgreSQL 18** as the pinned major version.
7. **Where the SQL tests live.**
8. **Who runs the migrations.** The migration role must be a superuser or the role that created the groups ([migration-safety.md](migration-safety.md)).
