# Database

PostgreSQL is the source of truth for the factory's jobs, stage runs, attempts, leases, evidence, approvals and audit trail. This directory documents the first schema, how to run its migrations, and what its tests prove.

- Status: the Slice 0 baseline (`s0-database-baseline`), row-level security and the revised state machine (`s1-database-tenancy-and-state-sync`, [ADR 0012](../adr/0012-row-level-security-in-slice-1.md) and [ADR 0010](../adr/0010-failure-escalation-routing-and-invalidation.md)), the alignment with the ports v1.1 store (`s1-database-port-alignment`, [ADR 0014](../adr/0014-ports-v1-1-claim-protocol-and-port-revision.md)), and the review at realistic volume (`s1-database-review`: measurements, one migration, the compatibility check, a retention proposal). Not yet reviewed by the software architect or the security specialist.
- Verified: see the table of runs in [running.md](running.md). Nineteen migrations applied, reverted and upgraded from the fourteenth with Diesel 2.3.11, and 967 checks in seventeen suites passed on PostgreSQL 18.6 (local cluster) on 2026-10-28. Docker and PostgreSQL 16 were not run for the last three packages.

## Where to start

| You want to | Read |
|---|---|
| Run the migrations or the tests | [running.md](running.md) |
| See the tables and how they relate | [data-model.md](data-model.md) |
| Know why a constraint or index exists | [constraints-and-indexes.md](constraints-and-indexes.md) |
| Understand how tenants are kept apart (keys and row-level security), the roles, and what is left open | [tenancy.md](tenancy.md) |
| Understand the evidence ledger and the audit log, and how to verify them | [ledger-and-audit.md](ledger-and-audit.md) |
| Write the storage crate against this schema: the recipes, and a table of the SQL, the pool and the constraint behind each `Store` method of ports v1.1 | [for-the-storage-crate.md](for-the-storage-crate.md) |
| Change the schema safely later | [migration-safety.md](migration-safety.md) |
| See the query plans on 10,000 and 100,000 rows, with row-level security on | [query-plans.md](query-plans.md) |
| See how long the hot queries take at 100,000 rows as the real logins, what row-level security costs, and what the concurrent appends, finders, relays and heartbeats do | [performance.md](performance.md) |
| Plan retention, archive and partitioning of the outbox, the ledger and the artifact metadata | [retention-and-partitioning.md](retention-and-partitioning.md) |
| Set connections, timeouts, statistics, autovacuum and backups | [operating-settings.md](operating-settings.md) |
| See what was found about each item ADR 0012 left unverified | [adr-0012-open-items.md](adr-0012-open-items.md) |
| Read the review that ties these together | [../reviews/database-review.md](../reviews/database-review.md) |
| Know what this work does not cover | [not-covered.md](not-covered.md) |

## What is in the repository

| Path | What it is |
|---|---|
| [`migrations/`](../../migrations/) | Nineteen Diesel migrations, each with `up.sql` and `down.sql`. Nine are the baseline, five came with row-level security (the supersede edge for skipped stage runs, then roles, tenant isolation, system scope, lookup functions), four are for ports v1.1 (the state machine rows `S21` and `S22`, the claim protocol, the Store model columns and rules, and the listing index) and one is from the review at realistic volume (the lease renewal as a heap-only update). |
| [`crates/storage/diesel.toml`](../../crates/storage/diesel.toml) | Diesel configuration: migrations directory and the generated schema path. |
| [`crates/storage/src/schema.rs`](../../crates/storage/src/schema.rs) | The schema as `diesel print-schema` writes it. Generated, never edited by hand. |
| [`scripts/db-test.sh`](../../scripts/db-test.sh) | Builds a throwaway database, migrates it and runs the suites. |
| [`scripts/db-perf.sh`](../../scripts/db-perf.sh), [`scripts/db-perf/`](../../scripts/db-perf/) | The measurement harness: a scratch cluster, deterministic data at 100,000 rows, the hot queries timed as the real logins, concurrency, churn, the partitioning prototypes, the dump and restore check. |
| [`scripts/db-compat-rust.sh`](../../scripts/db-compat-rust.sh) | Runs the storage crate of an earlier revision against later schemas. |
| [`tests/`](tests/) | The SQL for each suite, the test helpers, two catalog queries, `role_readiness.sql` (the start-up check of a pool's role), the files of the data-preserving upgrade test (`upgrade_fixture.sql`, `upgrade_fingerprint.sql`, `upgrade_check.sql`) and `compat_earlier_code.sql` (the earlier code's statements, run after each migration by the `compat` suite). |
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
9. **A ledger append does not raise the job's version** (migration 17), which departs from the wording of ADR 0008. The port's `append_ledger_entry` returns no version, so otherwise a transition after an append in one transaction would always conflict. See [constraints-and-indexes.md](constraints-and-indexes.md).
10. **The attempt limit counts from the last human answer** (migration 16), through a column the database sets when S13 moves a run to `READY`. The old absolute count would have refused the first attempt after an answer. See [constraints-and-indexes.md](constraints-and-indexes.md).
11. **The points that need the architect**, listed at the end of [for-the-storage-crate.md](for-the-storage-crate.md): the port cannot read or write the attestation, `ConstraintRule` lacks four codes, `update_job_facts` is write-once in the port and not in the data, and the A07 effect text in `state-machine.json` still says the epoch rises on a lost lease, which ADR 0014 says it does not.
12. **The retention and partitioning decisions D1 to D5** (is the outbox the long-term record, may an archived append-only record leave the live database, the retention periods, who builds the external anchor, and what replaces the ledger's two foreign keys), in [retention-and-partitioning.md](retention-and-partitioning.md); and **the claim's slowdown with READY runs of paused jobs** (finding F-01 of [../reviews/database-review.md](../reviews/database-review.md)): a state machine or protocol choice, not a schema one.
