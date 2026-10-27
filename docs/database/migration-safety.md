# Migration safety

- Status: the Slice 0 baseline (nine migrations) and the five migrations of `s1-database-tenancy-and-state-sync` (supersede edge, then row-level security in four parts). What the fourteen migrations do is tested. The rules for later migrations are guidance from the PostgreSQL documentation and from ADR 0007. They have not been exercised against an earlier schema with data, because there is none. The five new migrations are new files: nothing in the first nine was amended.
- Form: how-to guide and explanation.
- Source: [ADR 0007](../adr/0007-persistence-access-and-tenancy.md) rules 1 and 2 and the "Required tests" list, the [documentation policy](../reference/documentation-policy.md) row for data and schema migrations.

## What the migrations do

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
| 10 | `2026-10-27-001000_skipped_can_be_superseded` | The edge `SKIPPED` to `SUPERSEDED` (ADR 0010) and the terminal-row trigger rewritten to follow the supersede edges. Data only plus one `CREATE OR REPLACE FUNCTION`. |
| 11 | `2026-10-27-001100_rls_roles` | The groups `factory_system`, `factory_lookup`, `factory_resolver` (if missing). |
| 12 | `2026-10-27-001200_rls_tenant_isolation` | `ENABLE` and `FORCE ROW LEVEL SECURITY` and the policy `tenant_isolation` on the 17 tenant-owned tables; `ENABLE` and `tenant_self` on `tenants`. |
| 13 | `2026-10-27-001300_rls_system_scope` | The column grants and policies of `factory_system`. |
| 14 | `2026-10-27-001400_rls_lookup_functions` | The grants and policies of `factory_lookup`, the view `active_api_tokens` with the tenant check, `resolve_token` and `resolve_installation`, and their ownership and execute rights. |

The migrations are ordered so that each one creates objects that only depend on earlier ones. The two foreign keys that would otherwise form a cycle (`artifacts` to `stage_runs`, and `jobs` to `ledger_entries`) are added by `ALTER TABLE` in the later migration, and the second one is deferred.

### Locks and downtime

The baseline creates every object new, so no other session is using those tables while it runs and no lock makes anyone wait. Migrations 12 and 13 take `ACCESS EXCLUSIVE` on each tenant table for the length of an `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`, which is a catalog change and takes no longer than the lock wait; on a database that is serving traffic, run them in a quiet moment or with a `lock_timeout`. Migration 11 to 14 add no rows and rewrite no table. Its two `ALTER TABLE ... ADD CONSTRAINT ... FOREIGN KEY` statements lock both tables they touch while they validate, which on empty tables takes no time. There is no table rewrite, no data movement and no downtime. Nothing here has been timed on large data, because there is none yet.

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

The state lists are written out in more than one place, because a CHECK cannot read another table. A change to a status or a stage kind must update each of them:

| Where | What it repeats |
|---|---|
| `jobs_status_check`, `stage_runs_status_check`, `attempts_status_check`, `task_nodes_status_check` | The states of each machine |
| `jobs_terminal_check`, `stage_runs_terminal_check`, `attempts_terminal_check`, `task_nodes_terminal_check` | The terminal states |
| `stage_runs_stage_kind_check`, `jobs_pipeline_scope_check` | The 14 stage kinds |
| `jobs_open_idx` | The terminal job states, in its predicate |
| `attempts_one_active_per_stage_run`, `attempts_lease_expiry_idx`, `attempts_deadline_idx`, `attempts_teardown_idx`, and the CHECK `attempts_active_has_lease` | The live attempt states |
| `stage_runs_claim_idx` | The `READY` state |
| `stage_runs_guard` | Reads terminal states from `state_machine_states` and the supersede edges from `state_machine_edges`, so it follows the tables. A state that the JSON later marks `supersedable` needs one row in `state_machine_edges` (the way migration 10 added SKIPPED) and no new function |

The `statuses` suite compares the CHECK lists and the terminal lists with the JSON. It does not read the index predicates. Check those by hand.

## Row-level security and migrations

Every tenant-owned table has `FORCE ROW LEVEL SECURITY`, so the table owner, which runs the migrations, is bound by the policies. The policy names `factory_app` only, so **the owner sees no row of a tenant table and cannot write one** (measured: 2 rows without `FORCE`, 0 with it, for an owner that is not a superuser; a superuser bypasses it either way).

- **A migration that only changes structure** (a column, an index, a constraint) is not affected. `ALTER TABLE` does not read rows. A new `CHECK` or `NOT NULL` that validates existing rows does read them, and validation inside `ALTER TABLE` is not subject to policies.
- **A migration that moves or backfills data** reads and writes rows through the policy. Lift `FORCE` for that table for the length of the migration, and put it back, in the same migration (a migration is one transaction):

  ```sql
  ALTER TABLE jobs NO FORCE ROW LEVEL SECURITY;
  UPDATE jobs SET ... ;            -- as the owner, which now bypasses the policy
  ALTER TABLE jobs FORCE ROW LEVEL SECURITY;
  ```

  The `rls` suite checks the final state, so a forgotten `FORCE ROW LEVEL SECURITY` fails it. Prefer a backfill that the application does itself, one tenant at a time, under the policy.
- **A new tenant-owned table** needs, in the same migration: `ENABLE` and `FORCE ROW LEVEL SECURITY`, the policy `tenant_isolation` exactly as in migration 12, its grants, a line in `dbtest.mk_everything` and the new name in `expected_policies` of the `rls` suite. The suite fails on a table that lacks any of them.
- **A new loop for the system scope** needs its own policy, its own column grants, and a line in `rls` section 4.
- **Down scripts** must drop every policy they created. A full revert hides a forgotten one (the table is dropped later anyway), so the `migrations` suite also reverts the newest `j` migrations and runs them again, for each `j`. A leftover policy then makes the run fail with "already exists".

### Who runs the migrations

The migrations create roles (cluster wide), `REVOKE CREATE ON SCHEMA public FROM PUBLIC`, and hand two functions to `factory_lookup`. That needs one of:

1. **A superuser.** Nothing else to arrange.
2. **The role that created the groups**, on PostgreSQL 16 and later: creating a role gives its creator the ADMIN option on it, which is what lets migration 14 grant `factory_lookup` to itself for four statements and revoke it again. Tried here: a login with only `CREATEROLE` that owns the database ran all fourteen migrations, reverted them and ran them again.

A non-superuser that did not create the groups stops at migration 14 with a message that says so, before it changes anything. To use such a role, create the four groups first with the attributes in migration 11 and grant `factory_lookup` to the migration role with `WITH ADMIN OPTION`.

## Backward and forward compatibility of this baseline

- **Older code on a newer schema.** The application role has column-level `UPDATE` grants and inserts name their columns, so a new nullable column does not break old code. A new `NOT NULL` column without a default would, so avoid it in an expand step.
- **Newer code on an older schema** fails at start-up, because the application checks `__diesel_schema_migrations` (the role may read it).
- **Triggers that reject a new value.** The status machine trigger and the CHECK lists reject a state they do not know. That is the point, and it is why widening comes first.

## Going back

The `down.sql` files drop the tables and with them all the data. They exist so that `migration redo` works in development and so that the `migrations` suite proves a clean reverse. **They are not a rollback plan for a database that holds work.** In production, fix forward with a new migration, or restore from backup.

Two things stay after the full revert, on purpose:

- The four group roles (`factory_app`, `factory_system`, `factory_lookup`, `factory_resolver`). Roles belong to the cluster, and other databases may use them. The next `up` finds them and carries on, and refuses one that has gained a dangerous attribute.
- The `REVOKE CREATE ON SCHEMA public FROM PUBLIC` hardening, which is already the default on PostgreSQL 15 and later.

## Apply, verify and roll back, for the baseline

1. **Apply.** As the table owner, on an empty database: `diesel migration run --config-file crates/storage/diesel.toml`.
2. **Verify.** `SELECT count(*) FROM __diesel_schema_migrations` returns 14. `scripts/db-test.sh` passes against a database built the same way.
3. **Create the logins** as members of the groups ([for-the-storage-crate.md](for-the-storage-crate.md)): never one login in both `factory_app` and `factory_system`.
4. **Roll back.** `diesel migration revert --all`, which drops everything this set created. Use it only on a database that holds nothing worth keeping.

### Providing the roles

If the migrating login cannot create roles, create the groups first and the migrations only grant to them:

```sql
CREATE ROLE factory_app      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE factory_system   NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE factory_lookup   NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE factory_resolver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT factory_lookup TO <migration role> WITH ADMIN OPTION;
```

The migrations refuse a role of those names that has superuser, create-role, create-database, replication or bypass-row-security rights, or (for the three new ones) the right to log in.

## PostgreSQL versions

The full suite passed on 16.15 and 18.6. The schema uses `security_invoker` views (15 and later), `sha256()` (11), `gen_random_uuid()` (13), `hashtextextended()` (11) and identity columns (10). ADR 0007 leaves the choice between 17 and 18 to the DBA. **I recommend 18**, pinned as `postgres:18` in Compose and CI, because it is the version the tests ran on locally and in Docker. 17 sits between two versions that passed and was not run.
