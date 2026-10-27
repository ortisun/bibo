# Migration safety

- Status: baseline for Slice 0. What the first nine migrations do is tested. The rules for later migrations are guidance from the PostgreSQL documentation and from ADR 0007. They have not been exercised here, because there is no earlier schema to migrate from.
- Form: how-to guide and explanation.
- Source: [ADR 0007](../adr/0007-persistence-access-and-tenancy.md) rules 1 and 2 and the "Required tests" list, the [documentation policy](../reference/documentation-policy.md) row for data and schema migrations.

## What the first nine migrations do

| # | Directory under `migrations/` | Creates |
|---|---|---|
| 1 | `2026-10-27-000100_foundation` | The `factory_app` role (if missing), the state machine reference tables with their rows, and the generic trigger functions. |
| 2 | `2026-10-27-000200_tenancy_and_identity` | `tenants` (with the platform tenant), `repositories`, `principals`, `api_tokens`, the view `active_api_tokens`. |
| 3 | `2026-10-27-000300_artifacts_and_webhooks` | `artifacts`, `webhook_deliveries`. |
| 4 | `2026-10-27-000400_jobs_and_requests` | `jobs`, `original_requests`. |
| 5 | `2026-10-27-000500_stage_runs_attempts_tasks` | `stage_runs`, `stage_run_artifacts`, `attempts`, `task_nodes`, `task_node_dependencies`, and one foreign key added to `artifacts`. |
| 6 | `2026-10-27-000600_evidence_ledger` | `ledger_entries`, its views and verifier, and one foreign key added to `jobs`. |
| 7 | `2026-10-27-000700_audit_events` | `audit_events` and its verifier. |
| 8 | `2026-10-27-000800_outbox_inbox_approvals` | `outbox`, `inbox`, `approvals`. |
| 9 | `2026-10-27-000900_application_privileges` | Every grant of `factory_app`. |

The migrations are ordered so that each one creates objects that only depend on earlier ones. The two foreign keys that would otherwise form a cycle (`artifacts` to `stage_runs`, and `jobs` to `ledger_entries`) are added by `ALTER TABLE` in the later migration, and the second one is deferred.

### Locks and downtime

The baseline creates every object new, so no other session is using those tables while it runs and no lock makes anyone wait. Its two `ALTER TABLE ... ADD CONSTRAINT ... FOREIGN KEY` statements lock both tables they touch while they validate, which on empty tables takes no time. There is no table rewrite, no data movement and no downtime. Nothing here has been timed on large data, because there is none yet.

## Rules for every later migration

These follow ADR 0007's "expand, migrate, contract", so version N and version N + 1 of the code can run against the same schema during a rolling deploy.

1. **One direction of change per release.** Expand (add a nullable column, a new table, a wider CHECK list) in one release. Move data and switch the code in the next. Contract (drop the old column, narrow the CHECK) in a later one.
2. **Set a lock timeout.** Start a migration that touches a populated table with `SET LOCAL lock_timeout = '5s';` so it fails fast instead of queueing behind a long query and blocking every session behind it.
3. **Know what each statement locks.** The table below is from the PostgreSQL documentation, not from tests here.

   | Statement | Lock and effect | Safer form |
   |---|---|---|
   | `ADD COLUMN` nullable, or with a constant default | Brief `ACCESS EXCLUSIVE`, no rewrite on PostgreSQL 11 and later | Use as is |
   | `ADD COLUMN ... NOT NULL` without a default | Fails on a populated table | Add nullable, backfill in batches, then add the check as `NOT VALID` and validate |
   | `ADD CONSTRAINT ... CHECK` | `ACCESS EXCLUSIVE` while it scans the table | `NOT VALID`, then `VALIDATE CONSTRAINT`, which allows reads and writes |
   | `ADD CONSTRAINT ... FOREIGN KEY` | `SHARE ROW EXCLUSIVE` on both tables while it validates | `NOT VALID`, then `VALIDATE CONSTRAINT` |
   | `CREATE INDEX` | Blocks writes while it builds | `CREATE INDEX CONCURRENTLY` |
   | `CREATE TRIGGER` | `SHARE ROW EXCLUSIVE` | Brief; do it with a lock timeout |
   | `ALTER COLUMN TYPE` | Rewrites the table | Add a new column and migrate |

4. **Indexes created concurrently cannot run inside a transaction.** Diesel runs each migration in one. For such a migration add a `metadata.toml` next to `up.sql` and `down.sql` with `run_in_transaction = false`, and keep that migration to the one statement.
5. **Never edit a migration that has been applied anywhere.** Add a new one. The `migrations` suite would still pass on a clean database, but every other database would have a different history.
6. **Regenerate `schema.rs` in the same commit** (`scripts/db-test.sh write-schema`).
7. **Add a data-preserving upgrade test** for each migration after the baseline: load rows with the previous schema, run the new migration, and check the rows. ADR 0007 requires it. The baseline has no earlier version, so none exists yet.

### Changing the state machine

`state-machine.json` is the source of the statuses, stage kinds, transitions and event names. A change to it needs a migration that:

1. Widens first: add the new value to the `CHECK` list (add a new constraint `NOT VALID`, validate it, drop the old one) and insert the new rows into `state_machine_states`, `state_machine_transitions` and `state_machine_edges`. Deploy this before any code that can write the new value.
2. Narrows later, once no code writes the old value and no row holds it.

Regenerate the seed rows with `python3 -I docs/database/tools/state_machine_sql.py seed docs/architecture/state-machine.json`, and use only the difference in the new migration. The `statuses` suite compares the database with the JSON and fails if they differ, so a forgotten edit is caught the first time anyone runs it.

## Backward and forward compatibility of this baseline

- **Older code on a newer schema.** The application role has column-level `UPDATE` grants and inserts name their columns, so a new nullable column does not break old code. A new `NOT NULL` column without a default would, so avoid it in an expand step.
- **Newer code on an older schema** fails at start-up, because the application checks `__diesel_schema_migrations` (the role may read it).
- **Triggers that reject a new value.** The status machine trigger and the CHECK lists reject a state they do not know. That is the point, and it is why widening comes first.

## Going back

The `down.sql` files drop the tables and with them all the data. They exist so that `migration redo` works in development and so that the `migrations` suite proves a clean reverse. **They are not a rollback plan for a database that holds work.** In production, fix forward with a new migration, or restore from backup.

Two things stay after the full revert, on purpose:

- The `factory_app` role. Roles belong to the cluster, and other databases may use them. The next `up` finds the role and carries on.
- The `REVOKE CREATE ON SCHEMA public FROM PUBLIC` hardening, which is already the default on PostgreSQL 15 and later.

## Apply, verify and roll back, for the baseline

1. **Apply.** As the table owner, on an empty database: `diesel migration run --config-file crates/storage/diesel.toml`.
2. **Verify.** `SELECT count(*) FROM __diesel_schema_migrations` returns 9. `scripts/db-test.sh` passes against a database built the same way.
3. **Create a login** for each service as a member of `factory_app`.
4. **Roll back.** `diesel migration revert --all`, which drops everything this set created. Use it only on a database that holds nothing worth keeping.

### Providing the role

If the migrating login cannot create roles, create `factory_app` first and the migration only grants to it:

```sql
CREATE ROLE factory_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
```

The migration refuses a role of that name that has superuser, create-role, create-database, replication or bypass-row-security rights.

## PostgreSQL versions

The full suite passed on 16.15 and 18.6. The schema uses `security_invoker` views (15 and later), `sha256()` (11), `gen_random_uuid()` (13), `hashtextextended()` (11) and identity columns (10). ADR 0007 leaves the choice between 17 and 18 to the DBA. **I recommend 18**, pinned as `postgres:18` in Compose and CI, because it is the version the tests ran on locally and in Docker. 17 sits between two versions that passed and was not run.
