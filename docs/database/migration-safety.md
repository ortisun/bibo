# Migration safety

- Status: the Slice 0 baseline (nine migrations), the five migrations of `s1-database-tenancy-and-state-sync` (supersede edge, then row-level security in four parts), the four of `s1-database-port-alignment` (state machine rows, claim protocol, Store model, listings) and the one of `s1-database-review` (migration 19). What the nineteen migrations do is tested. The rules for later migrations are guidance from the PostgreSQL documentation and from ADR 0007; since `s1-database-review` they are exercised, one migration at a time, against the earlier code (`scripts/db-test.sh compat`, and the section "Version N-1 code on version N schema" below). Nothing already applied was amended.
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
| 15 | `2026-10-27-001500_state_machine_blocked_and_reauthorization` | The transitions `S21` and `S22` and their edges (ports v1.1). Data only. |
| 16 | `2026-10-27-001600_claim_protocol` | `stage_runs.attempts_before_last_answer`; the claim index replaced by `(not_before, id)`; `stage_runs_guard`, `attempts_insert_guard`, `attempts_update_guard` and `attempts_epoch_check` replaced by stricter versions; the deferred live-attempt check on `stage_runs` and `attempts`. |
| 17 | `2026-10-27-001700_store_model` | `stage_runs.failing_set_sha256` and the BLOCKED outcome rule; the two attestation columns on `repositories` with their trigger; the task node rules; `jobs_bump_guard` in place of `bump_guard` on `jobs`; grants for the new columns. Constraints added `NOT VALID` and then validated. |
| 18 | `2026-10-27-001800_listings` | The index `jobs_repository_listing_idx`. |
| 19 | `2026-10-28-001900_lease_renewal_is_heap_only` | Drops the index `attempts_lease_expiry_idx`, so that a lease renewal can be a heap-only update (`s1-database-review`; measured in [performance.md](performance.md)). Changes a plan, not a statement. |

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
7. **Add a data-preserving upgrade test** for each migration after the baseline: load rows with the previous schema, run the new migration, and check the rows. ADR 0007 requires it. The `migrations` suite does it for migrations 15 to 18: it builds the schema as it was after migration 14 (`UPGRADE_FROM` in `scripts/db-test.sh`), writes rows into every tenant-owned table with the statements of that time (`tests/upgrade_fixture.sql`), runs the newer migrations, compares a hash of every table over the columns it had before (`tests/upgrade_fingerprint.sql`), and checks that the new columns hold their defaults and that the earlier code's claim, renewal and head move still work (`tests/upgrade_check.sql`). The next package moves `UPGRADE_FROM` forward.

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
| `attempts_one_active_per_stage_run`, `attempts_deadline_idx`, `attempts_teardown_idx`, and the CHECK `attempts_active_has_lease` (the lease expiry sweep reads the live set through one of the first two since migration 19) | The live attempt states |
| `stage_runs_claim_order_idx` (migration 16; it replaced `stage_runs_claim_idx`), `stage_run_live_attempt_check` (the states that may hold a live attempt: `RUNNING`, `SUPERSEDED`) | The `READY` state; the states with a live attempt |
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

## Version N-1 code on version N schema: the rule, the check and the matrix

Added by `s1-database-review` (2026-10-28).

### The rule for every later migration

1. **The order of a deploy is: migrate, then roll out the code.** The migration is a deploy step, not part of the application (ADR 0007, rule 1). While the new code rolls out, and for as long as anyone wants to be able to roll the code back, **the code of the previous release runs on the new schema**. A migration is therefore allowed to add and to relax, in one step, and to nothing else.
2. **One step (compatible with the earlier code):** a new table; a new nullable column or a column with a constant default; a new index (created `CONCURRENTLY` on a busy table); a `CHECK` or foreign key added `NOT VALID` and validated; a wider `CHECK` list; a new function under a new name; a function replaced by one that accepts everything the old one accepted; a trigger that rejects only what the earlier code never writes; an index dropped that no earlier statement needs by name (a plan changes, a statement does not); a new grant.
3. **Two steps (expand now, contract in a later release):** dropping or renaming a column, table or index the earlier code names; narrowing a `CHECK` list; `NOT NULL` on an existing column; a changed type; a function whose result or effect changes for an input the earlier code sends; a trigger or constraint that rejects a write the earlier code makes; a `REVOKE`; a removed state machine value or edge. The expand migration ships with the code that stops using the old shape; the contract migration ships a release later, and its pull request names the release whose code is gone.
4. **The exception that is on purpose:** migrations 12 to 14 (row-level security). Code that never sets `factory.tenant_id` sees no row after them (the `rls` suite shows it), so they are compatible only with code that sets it. The order that makes them safe is the reverse of the usual one: the code that sets the tenant ships first (the setting is harmless before the policies exist), then the migration.
5. **Start-up check.** The storage crate refuses a database that is *behind* its migration list and accepts one that is *ahead* (`readiness::check_schema`). An earlier binary therefore starts on a newer schema; this was run (the matrix below).

### The check

- **At SQL level, one migration at a time: `scripts/db-test.sh compat`.** It builds the schema as it was after migration 14, writes a row in every tenant-owned table with the statements of that time, applies migrations 15 to 19 **one by one**, and after each one checks that every table still holds its rows byte for byte over the columns it had, and that the statements of the code written for migration 14 (the claim as a swap and an attempt, the lease renewal, the ledger head move with a version bump, a raised budget, the timeline reads, in [tests/compat_earlier_code.sql](tests/compat_earlier_code.sql)) still run. The first line is a control: the same statements on the schema they were written for. A migration that renames a column the earlier code uses fails both checks (shown: a `RENAME COLUMN last_heartbeat_at` migration, added for the run and removed, failed with `column "last_heartbeat_at" of relation "attempts" does not exist` and with changed rows over the old columns).
- **With real earlier code: `scripts/db-compat-rust.sh`.** It exports the storage crate as it was at the revision `53c0938` (the last commit written for the schema after migration 14, ports v1) with `git archive`, builds its 11 integration test binaries offline, replaces the migrations folder its tests read by the first *S* migrations of this checkout, and runs the binaries at S = 14 (the control) to 19. The tests connect as the three real logins. It leaves the working tree alone.
- **Moving the baseline.** `UPGRADE_FROM` in `scripts/db-test.sh` names the schema the earlier code was written for. When a release is cut, the release package moves it to that release's last migration, replaces `compat_earlier_code.sql` and `upgrade_fixture.sql` with the statements and rows of that release's code, and passes `--code-rev <release tag>` to the Rust runner.

### The matrix

Earlier code = the code written for the schema after migration 14. "SQL" is `scripts/db-test.sh compat`; "Rust" is `scripts/db-compat-rust.sh` (49 tests at the control; the full table is in [../reviews/database-review.md](../reviews/database-review.md)).

| Migration | What it does | Kind | Earlier code on it |
|---|---|---|---|
| 1 to 9 | The baseline | no earlier code | not applicable |
| 10 | Supersede edge for skipped runs; one function replaced | expand | no code existed before it; not tested |
| 11 | The three more group roles | expand | not tested (no code existed) |
| 12, 13, 14 | Row-level security: tenant isolation, system scope, lookups | **coordinated**, rule 4 | not compatible with code that does not set the tenant, by design (ADR 0012); the `rls` suite proves it |
| 15 | `S21`, `S22` rows | expand, data only | SQL pass; Rust pass |
| 16 | Claim protocol: a column with a default, a superset index, stricter guards | expand (the guards reject only writes no earlier code makes) | SQL pass; Rust pass, including the 13 claim and lease tests |
| 17 | Store model: nullable columns, constraints added `NOT VALID` and validated, `jobs_bump_guard` in place of `bump_guard` | expand | SQL pass; Rust pass |
| 18 | `jobs_repository_listing_idx` | expand | SQL pass; Rust pass |
| 19 | Drops `attempts_lease_expiry_idx` | one step, a plan changes | SQL pass; Rust pass |

One Rust test fails from schema 15 on: `tenant_isolation::refuses_a_role_that_bypasses_rls`. It is the test's simulation, not the code: to show that a database *behind* the code is refused, it deletes the newest row of `__diesel_schema_migrations`. Once the schema is ahead of the code, that row is one the old code does not list, and the code correctly starts (`Ok`, expected `SchemaBehind { missing: 1 }`). The test must delete a version the code embeds. The same line is in the current test, where it passes only because the code and the schema agree on 19; it will fail the day a migration lands without a code change. `crates/storage/tests` belongs to the storage package, so it is reported, not changed.

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

## Migrations 15 to 18: what they lock and why they are an expand step

- **Nothing is removed.** One index is replaced by a superset (`stage_runs_claim_idx (not_before)` by `(not_before, id)`), so code that ordered by `not_before` alone still uses it. Functions are replaced by versions that accept everything the old ones accepted except the writes that the new protocol makes wrong (a back-off outside `READY`, a second attempt past the limit counted from the last answer, a live attempt left behind by a run that moved on). No deployed code makes those writes.
- **Locks.** Each migration sets `lock_timeout = '5s'`. `ADD COLUMN` with a constant default or a nullable column takes a brief `ACCESS EXCLUSIVE` and no rewrite. The new `CHECK` and foreign key constraints are added `NOT VALID` and then validated, which lets reads and writes go on. `CREATE INDEX` in migration 16 and 18 blocks writes to `stage_runs` and `jobs` while it builds: on a busy table run it as `CREATE INDEX CONCURRENTLY` in a migration of its own with `run_in_transaction = false`. Today both tables are small.
- **Version N and N + 1 on one schema.** The older code's claim (a swap with the epoch raised, then the attempt), its renewal, its head move with a version bump and a raised budget on a run all still work after the upgrade; the `migrations` suite runs them. The newer code on the older schema fails at start-up on the migration count.
- **A decision to confirm:** migration 17 lets a ledger append leave the job's version alone. Reverting it is `down.sql` of that migration (and nothing else), because no table depends on the change.
