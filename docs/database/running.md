# Running the migrations and the database tests

- Status: every command below was run on 2026-10-27 on a macOS laptop. Results are in the last section. Written for the baseline and revised for the work packages `s1-database-tenancy-and-state-sync` and `s1-database-port-alignment`.
- Form: how-to guide.
- Goal: apply the migrations to a PostgreSQL database, run the database tests, and regenerate `schema.rs`.

## Prerequisites

| Tool | Version used | Needed for |
|---|---|---|
| PostgreSQL server | 18.6 (Homebrew, local cluster) and 18.6 in Docker (`postgres:18`); 16.15 in Docker (`postgres:16-alpine`) is listed in the results. 17 was not run. | The tests need a server and the superuser role. |
| `psql` | 18.6 (16 or later for the `rls` suite, which uses `\bind`; older gives BLOCKED) | Every suite. |
| Diesel CLI | 2.3.11 | Running migrations and `diesel print-schema`. |
| Python 3 | 3.15.0 (standard library only) | Generating the expected values from `state-machine.json` and the outside check of the audit chain. |
| Docker | 29.9.2 | Only when no local PostgreSQL binaries exist or `FACTORY_DB_PROVISION=docker` is set. |

The Diesel CLI is pinned. Install the same version, with only the PostgreSQL backend so it does not need MySQL or SQLite libraries:

```bash
cargo install diesel_cli --version 2.3.11 --locked --no-default-features --features postgres
```

The script warns when the installed CLI has another version, because `schema.rs` may be formatted differently. The warning does not stop the run. A difference in `schema.rs` does.

## Run the migrations by hand

1. Create an empty database and note its URL. For a throwaway one: `createdb factory_dev` and `export DATABASE_URL=postgres://localhost/factory_dev`.
2. Apply every migration, as the role that will own the tables:

   ```bash
   diesel migration run --config-file crates/storage/diesel.toml
   ```

   Diesel rewrites `crates/storage/src/schema.rs` after the run, because the config asks for it. Add `--locked-schema` to fail instead of rewriting.
3. To check the down migrations, run `diesel migration redo --all --config-file crates/storage/diesel.toml`. It reverts every migration and applies them again.
4. Never run the migrations from the application. Applications check the schema version at start-up and refuse to become ready if it is behind (ADR 0007).

Expected result of step 2: eighteen `Running migration` lines, the last one `2026-10-27-001800_listings`. Verify with `psql "$DATABASE_URL" -c 'select version from __diesel_schema_migrations order by version'`.

The role that runs them must be a superuser or the role that created the four groups ([migration-safety.md](migration-safety.md)). After they ran, create the logins: [for-the-storage-crate.md](for-the-storage-crate.md).

## Run the database tests

1. From the repository root run the whole script:

   ```bash
   scripts/db-test.sh
   ```

   It provides a database, migrates it, runs the sixteen suites, drops everything it created (the databases, and the login roles the `rls` suite makes), and prints a last line that starts with `PASS` or `FAIL`.
2. To run some suites only, name them. `scripts/db-test.sh ledger audit` runs two. `scripts/db-test.sh --list` prints all sixteen with one line each on what they prove.
3. To keep the server for inspection use `--keep`. It prints the URL of the maintenance database and leaves the process running, and you stop it yourself.

### Where the database comes from

The script picks the first of these that works:

1. `FACTORY_DB_ADMIN_URL`, a superuser URL of a server you provide, such as `postgres://postgres@localhost:5432/postgres`. The script creates and drops only databases named `factory_t_*` and `factory_tpl_*`. Use this in CI with a service container. **Do not point it at a server that matters.** The tests create the cluster-wide role `factory_app`, create and drop test roles, and switch superuser-only session settings. The script leaves `factory_app` behind on purpose.
2. A private local cluster. The script looks for `initdb`, `pg_ctl` and `postgres` in `FACTORY_PG_BIN`, on `PATH`, and in the usual Homebrew and Debian directories. It starts a cluster on a unix socket in a mode 0700 directory, with TCP off and `fsync` off, and stops and deletes it at the end.
3. Docker, with the image in `FACTORY_DB_IMAGE` (default `postgres:18`), published on a random loopback port with a random password.

`FACTORY_DB_PROVISION=local`, `docker` or `none` forces one of them or turns provisioning off. `FACTORY_DB_LEASE_ROUNDS` (default 25) sets how many contested claims the lease suite makes. `FACTORY_DB_PLANS_SCALE` (default 1) sets the size of the plans suite: 1 is 10,000 rows in each large table, 10 is 100,000 and takes about three minutes.

The `rls` suite opens sessions as real login roles (`dbtest_app_*`, `dbtest_system_*`, `dbtest_api_*`) with a random password, over the same address as the superuser connection. They are cluster wide, so the script drops them when it ends, also on Ctrl-C. On a server you provide, a run that was killed with `kill -9` leaves them behind; drop the `dbtest_*` roles by hand.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Every suite passed. |
| 1 | A check failed. The output ends with `FAIL:` and the suite names. |
| 2 | Bad usage. |
| 3 | **BLOCKED.** No database is reachable, a needed tool is missing (`psql`, `python3`, `diesel`), or the database user is not a superuser. The output says `BLOCKED:` and what is missing. Nothing was verified. CI must treat code 3 as a failure. |

### The suites and the done criteria of the work package

| Command | What it proves |
|---|---|
| `scripts/db-test.sh migrations` | Up, revert all, up again and redo on an empty database; the catalog is identical afterwards, also after reverting only the newest `j` migrations; the committed `schema.rs` equals `diesel print-schema`; **a data-preserving upgrade**: the schema as it was after migration 14, a row in every tenant-owned table, the newer migrations, every row unchanged over its old columns, the earlier code's statements still working. |
| `scripts/db-test.sh statuses` | An unknown status is rejected on every status column; the allowed values, the transitions (`S21` and `S22` included), the edges and the event names equal `state-machine.json`. |
| `scripts/db-test.sh outbox` | The outbox is atomic with the state change, immutable and consumer idempotent; the foreign key accepts `stage_run.blocked` for `S21` and `stage_run.waiting_for_human` for `S22`, and no other pairing. |
| `scripts/db-test.sh lease rls` | `lease`: the candidate search and the `start_attempt` statement sequence as the system and application roles, the three due-attempt queries and their moves, postponement, the window after a human answer, S21, S22, and four-worker races with one winner. `rls`: the same sequence through two real logins, 12 rounds of four workers, and the due queries as the system role. |
| `scripts/db-test.sh privileges tenancy` | The tenant role may write the new columns and the system role may not; composite keys include the tenant. |
| `scripts/db-test.sh store_model` | The tables carry what the Store port of ports v1.1 needs, and the SQL of each operation that needs only the existing tables runs as the application role. |
| `scripts/db-test.sh ledger` | `UPDATE` and `DELETE` on the ledger fail for the application role, and a gapped insert fails. |
| `scripts/db-test.sh tenancy` | A foreign key into another tenant's row is rejected, also for a session under row-level security, and unique keys include the tenant. Foreign key checks bypass row security. |
| `scripts/db-test.sh rls` | Every table with a tenant column, found from the catalog, is isolated; the roles, the system scope and the two lookup functions; real logins, a reused connection and a claim race through two logins (NT-TEN-01, database part). |
| `scripts/db-test.sh terminal_rows` | `UPDATE` of a terminal stage run fails except for the supersede transition, and every move out of a terminal state is checked against `state-machine.json`. |
| `scripts/db-test.sh plans` | The claim, sweep, timeline and ledger-tail queries use index scans on 10,000 generated rows (100,000 with `FACTORY_DB_PLANS_SCALE=10`), as the roles that run them, with row-level security on. |
| `scripts/db-test.sh audit` | The application role can only `INSERT` and `SELECT` on the audit table (NT-AUD-01). |
| `scripts/db-test.sh webhook_delivery` | A second delivery with the same id violates a unique constraint and creates no second job or outbox row. |

Eight more suites go beyond the original criteria: `lease`, `outbox`, `approvals`, `tokens`, `privileges`, `contracts`, `rls` and `store_model`.

## Run the Rust suites that need this database

Two Rust suites run on `PgStore` with a database of their own per check or scenario. They use the same server rules as `scripts/db-test.sh` (a local PostgreSQL install, then Docker, and a `BLOCKED:` panic when neither exists, never a pass).

```bash
# The Store contract suite, the same checks the in-memory fake passes.
cargo nextest run -p factory-storage --test store_contract

# The engine scenario suite on PostgreSQL: the same source as the in-memory run
# (crates/workflow/tests/engine_scenarios/body.rs), 96 of its 97 scenarios.
cargo nextest run -p factory-worker --test engine_scenarios_all_on_postgres
```

The scenario suite connects with the API login, because one scenario records a webhook rejection under the platform tenant and only that login may. `FACTORY_SCENARIO_LOGIN=worker` connects as the worker does; that scenario is then refused by design and the rest pass.

The server's clock cannot be set, so a scenario that waits past a lease, a deadline, a back-off or an approval's expiry moves every stored time that those rules read back by the same amount (the same repair the contract runner makes, with the triggers off for one transaction). The engine must therefore decide on the row it read in its transaction, never on a copy it carried from before the clock moved.

## Regenerate `schema.rs`

1. Run `scripts/db-test.sh write-schema`. It migrates a throwaway database and writes the output of `diesel print-schema` to `crates/storage/src/schema.rs`.
2. Commit the file with the migration that caused the change. Never edit it by hand: the `migrations` suite compares it with a fresh `print-schema`.

## Expected output

A passing run ends like this (the number of checks changes when a test is added):

```text
PASS: migrations statuses ledger tenancy rls terminal_rows plans audit webhook_delivery lease outbox approvals tokens privileges contracts store_model (923 checks, PostgreSQL 18.6 (Homebrew), local)
```

A failing check prints `NOT OK - <what was expected>: <what happened>` and the statement, and the run exits 1.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `BLOCKED: the diesel CLI is not installed` | Install the pinned CLI with the command above. |
| `BLOCKED: no PostgreSQL server` | Install PostgreSQL 16 or later, or start Docker, or set `FACTORY_DB_ADMIN_URL`. |
| `BLOCKED: the database user must be a superuser` | The tests create roles and switch session settings. Give them a throwaway server. |
| `initdb: error: program "postgres" is needed by initdb` | The `initdb` on `PATH` comes from a client-only package such as Homebrew `libpq`. The script skips it and looks for a full install. |
| `crates/storage/src/schema.rs differs from diesel print-schema` | A migration changed and the file was not regenerated, or the CLI version differs. Run `write-schema` and read the diff. |
| `the race barrier failed` | Fewer sessions than expected reached the start line, usually because `max_connections` is too low. The script's own cluster allows 120. Raise it on a server you provide. |
| Tests leave databases behind | They are named `factory_t_*` or `factory_tpl_*`. Drop them. A normal run and a Ctrl-C both clean up. |
| `role "factory_app" already exists` with other attributes (or `factory_system`, `factory_lookup`, `factory_resolver`) | The migration refuses a role with superuser, create-role, create-database, replication or bypass-RLS rights, and the three newer groups also with the right to log in. Fix the role. |
| `run this migration as a superuser, or as the role that created factory_lookup` | Migration 14 hands two functions to `factory_lookup` and needs the right to become it. See [migration-safety.md](migration-safety.md). |
| `permission denied for table ...` in the `rls` output for the system role | Intended in most places. The suite lists what the system role may read; a new loop needs a migration. |
| Leftover `dbtest_*` roles on a server you provide | A run was killed hard. `DROP ROLE` them. |

## Results of the runs

Run on 2026-10-27 after the last commit of the work package `s1-database-tenancy-and-state-sync`. The earlier baseline (510 checks, 14 suites, nine migrations) is in the history of this page.

| Provider | PostgreSQL | Command | Result |
|---|---|---|---|
| Local cluster (Homebrew) | 18.6 | `scripts/db-test.sh`, twice in a row | pass both times, 679 checks in 15 suites, 22 and 23 seconds |
| Local cluster, persistent server | 18.6 | `FACTORY_DB_ADMIN_URL=... scripts/db-test.sh`, twice in a row | pass both times; afterwards no test database, no `dbtest_*` login and no group membership remains, only the four group roles |
| Docker `postgres:18` | 18.6 (Debian) | `FACTORY_DB_PROVISION=docker scripts/db-test.sh` | pass, 679 checks, container removed. The `rls` suite logs in over TCP with a password here |
| Docker `postgres:16-alpine` | 16.15 | `FACTORY_DB_PROVISION=docker FACTORY_DB_IMAGE=postgres:16-alpine scripts/db-test.sh` | pass, 679 checks, container removed |
| Local cluster | 18.6 | `scripts/db-test.sh plans` | pass, 28 checks |
| Local cluster | 18.6 | `FACTORY_DB_PLANS_SCALE=10 scripts/db-test.sh plans` | pass, 28 checks, 191 seconds |
| Plain `CREATEROLE` database owner that created the groups | 18.6 | all fourteen `up.sql`, then all `down.sql`, then all `up.sql`, with `psql` | all three passes ran. The same owner without having created the groups stops at migration 14 with the message that says why |
| No database (`FACTORY_DB_PROVISION=none`), unreachable server, no Diesel CLI on `PATH` | | `scripts/db-test.sh ledger` | exit code 3 and `BLOCKED:` each time (baseline run; not repeated) |
| Deliberate breaks of the schema | 18.6 | each break plus the suites that should notice it | the baseline ran ten, all exit 1. The second package ran seventeen more, listed below |

### Deliberate breaks of the row-level security work

Each was made by editing one migration, running the suites that should notice, and restoring the file. All exited 1 except one that the suite did not see at first.

| Break | Suite | First failing check |
|---|---|---|
| A policy is not created for `jobs` (RLS left on) | `rls` | `[jobs] there is no policy tenant_isolation; tenant 1 sees rows=0, expected only its 1 rows ...` |
| Row-level security never enabled on `approvals` | `rls` | `[approvals] row-level security is not enabled; FORCE ROW LEVEL SECURITY is not set ...` |
| `FORCE` skipped for `ledger_entries` | `rls` | `[ledger_entries] FORCE ROW LEVEL SECURITY is not set (the table owner is not bound)` |
| `NULLIF` dropped from every policy | `rls` | `USING is (tenant_id = (current_setting(...))::uuid), not the NULLIF form` (and, by probe, the second transaction on a reused connection fails with `invalid input syntax for type uuid: ""`) |
| `BYPASSRLS` on `factory_app` | `rls` | `factory_app is a NOLOGIN group ... got has BYPASSRLS;` |
| `BYPASSRLS` on `factory_system` | `rls` | `factory_system ... got has BYPASSRLS;` |
| `resolve_token` without `SET search_path` | `rls` | `... got true s factory_lookup NO CONFIG` |
| `resolve_installation` executable by `PUBLIC` | `rls` | `expected factory_lookup,factory_resolver, got PUBLIC,factory_lookup,factory_resolver` |
| `resolve_token` executable by `factory_app` | `rls` | `... got factory_app,factory_lookup,factory_resolver` |
| `factory_system` may update `status`, `version`, `lease_epoch` of stage runs | `rls` | `factory_system holds no column privilege beyond the expected list: got stage_runs.lease_epoch:UPDATE, ...` |
| The lock policy on `stage_runs` says `WITH CHECK (true)` | `rls` | `the system role can take the lock but a row it updated would be refused by the policy: condition is false` |
| `factory_system` may read the ledger | `rls` | `factory_system holds no table privilege beyond the expected list: got ledger_entries:SELECT` |
| `tenants` left without row-level security | `rls` | `the policies in the database are exactly the policies on the list: ...` |
| `active_api_tokens` without `security_invoker` | `rls` | `every view ... runs with the caller's rights: got active_api_tokens` |
| A login in both `factory_app` and `factory_system` | `rls` | `break_both_login is a member of both factory_app and factory_system` |
| The edge `SKIPPED` to `SUPERSEDED` left out of the migration | `statuses`, `terminal_rows` | `state_machine_edges equals state-machine.json ...: expected 0, got 1` |
| The down script of the system migration forgets one policy | `migrations` | **Not seen by the first version**: a full revert drops the table and the policy with it, so the run passed. The suite now reverts the newest `j` migrations and runs them again; the break then fails with `running the 2 newest migrations again after reverting them failed (a down script left something behind?)` |

### Runs of the work package `s1-database-port-alignment`

Run on 2026-10-27 on the local Homebrew cluster, PostgreSQL 18.6. Docker and PostgreSQL 16 were not run for this package.

| Command | Result |
|---|---|
| `scripts/db-test.sh`, twice in a row | pass both times, 923 checks in 16 suites, 24 and 23 seconds |
| `scripts/db-test.sh statuses outbox` (the starting point failed by design on `S21` and `S22`) | pass, 86 checks after migration 15 |
| `scripts/db-test.sh plans` | pass, 43 checks at 10,000 rows |
| `FACTORY_DB_PLANS_SCALE=10 scripts/db-test.sh plans` | pass, 43 checks (plans in [query-plans.md](query-plans.md)). The data now includes 100,000 task nodes and 80,000 edges, 20,000 approvals, original requests and deliveries, so the run is slower than the 191 seconds of the earlier package |
| `pyright docs/database/tools/*.py`; `shellcheck --severity=warning scripts/db-test.sh` | 0 errors, 0 warnings; clean |
| `cargo fmt --all -- --check`; `cargo xtask check-architecture` | pass; pass |

### Deliberate breaks of the port alignment work

Each was made in a copy of the package (migrations, tests and script), by changing one thing, running the suite that should notice, and discarding the copy. All 26 exited 1 and each failing check is the one that names the damaged rule. The runner is a 150-line script kept outside the repository (it is a tool for this review, not part of the build); the table is its output.

| Break | Suite | First failing check |
|---|---|---|
| The live-attempt rule never fires | `lease` | `S05 while the attempt is still live is refused at commit: the statement succeeded but had to fail` |
| The attempt limit counts every attempt again | `lease` | `stage run allows 1 attempts since the last human answer, this would be number 2` (the first attempt after an answer is refused) |
| `not_before` may change on any run | `lease` | `not_before cannot change on a RUNNING run: the statement succeeded but had to fail` |
| An update that keeps the status may change anything | `lease` | `a READY run cannot change anything else without a status move: the statement succeeded but had to fail` |
| A leaked sandbox can be recorded as gone | `lease` | `leaked cannot go back to false: the statement succeeded but had to fail` |
| The epoch check judges the row as queued again | `lease` | `attempt ... holds lease epoch 1 but the stage run is at epoch 2` |
| The claim index is dropped | `plans` | `claim: READY stage runs ...: the plan does not use index stage_runs_claim_order_idx` |
| The edge READY to S22 is left out | `statuses` | `state_machine_edges equals state-machine.json: expected 0, got 1` |
| The outbox may announce S21 under the wrong event | `outbox` | `S21 (RUNNING to BLOCKED) can emit stage_run.blocked: the foreign key accepts it: the statement failed with 23503` |
| A failing set is accepted with any outcome | `store_model` | `failing_set_sha256 with the PASSED outcome is refused: the statement succeeded but had to fail` |
| A BLOCKED run may carry any outcome | `store_model` | `S21 without a gate outcome is refused: the statement succeeded but had to fail` |
| A service principal may attest | `store_model` | `a service principal cannot attest: the statement succeeded but had to fail` |
| The caller's attestation time is kept | `store_model` | `attesting again after clearing stamps the database time: expected true, got false` (**not caught by the first version of the suite**, which only tried the caller's time when the attestor did not change) |
| A RUNNING task node may have no attempt | `store_model` | `T02 without the attempt is refused: the statement succeeded but had to fail` |
| A SUCCEEDED task node may have no commit | `store_model` | `T03 without a commit is refused: the statement succeeded but had to fail` |
| A ledger head move cannot skip the version bump | `store_model` | `jobs version must rise by exactly one (was 2, update set 2), or stay when only the ledger head moves` |
| The ledger head may move back | `store_model` | `the head never moves back, with or without a version bump: the statement succeeded but had to fail` |
| The repository listing index is dropped | `plans` | `list_jobs: one repository: the plan does not use index jobs_repository_listing_idx` |
| The system role may write the failing set | `rls` | `factory_system holds no column privilege beyond the expected list: got stage_runs.failing_set_sha256:UPDATE` |
| The system role may read the attestation | `rls` | `factory_system holds no column privilege beyond the expected list: got repositories.bypass_attested_at:SELECT` |
| The tenant role is not given the new column grant | `privileges` | `factory_app holds every column UPDATE privilege on the expected list: got stage_runs.failing_set_sha256` |
| A new tenant table with no row-level security (the suite's own count and fixtures updated, so the per-table check is what fails) | `rls` | `all 17 tenant-owned tables are isolated ...: got [probe_notes] row-level security is not enabled ...` |
| A new tenant table with row-level security enabled but not forced | `rls` | `... got [probe_notes] FORCE ROW LEVEL SECURITY is not set ...` |
| A new tenant table whose foreign key does not carry the tenant | `tenancy` | `all 33 foreign keys between tenant-owned tables join tenant_id to tenant_id: got probe_notes.probe_notes_repo_fkey` |
| A migration that changes an existing row while it upgrades | `migrations` | `upgrade: rows changed while the newer migrations ran` (the migration rewrites a column of a repository; the hash of the table over its old columns differs) |
| A migration that breaks a statement of the earlier code | `migrations` | `the earlier head move with a version bump is still accepted: expected rows=1, got ERR:23514 ...` |

Two things the first version of the breaks showed. The break of the attestation time passed (rc 0) and drove a new check. And three of the breaks (the two index drops and the foreign key without the tenant) first failed at the template migration for a bad patch, which proves nothing about the suite: they were rewritten so that the migration runs and the suite's own check is what fails.
