# Running the migrations and the database tests

- Status: every command below was run on 2026-10-27 on a macOS laptop. Results are in the last section.
- Form: how-to guide.
- Goal: apply the migrations to a PostgreSQL database, run the database tests, and regenerate `schema.rs`.

## Prerequisites

| Tool | Version used | Needed for |
|---|---|---|
| PostgreSQL server | 18.6 (Homebrew, local cluster) and 18.6 in Docker (`postgres:18`); 16.15 in Docker (`postgres:16-alpine`) also passed. 17 was not run. | The tests need a server and the superuser role. |
| `psql` | 18.6 | Every suite. |
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

Expected result of step 2: nine `Running migration` lines, the last one `2026-10-27-000900_application_privileges`. Verify with `psql "$DATABASE_URL" -c 'select version from __diesel_schema_migrations order by version'`.

## Run the database tests

1. From the repository root run the whole script:

   ```bash
   scripts/db-test.sh
   ```

   It provides a database, migrates it, runs the fourteen suites, drops everything it created, and prints a last line that starts with `PASS` or `FAIL`.
2. To run some suites only, name them. `scripts/db-test.sh ledger audit` runs two. `scripts/db-test.sh --list` prints all fourteen with one line each on what they prove.
3. To keep the server for inspection use `--keep`. It prints the URL of the maintenance database and leaves the process running, and you stop it yourself.

### Where the database comes from

The script picks the first of these that works:

1. `FACTORY_DB_ADMIN_URL`, a superuser URL of a server you provide, such as `postgres://postgres@localhost:5432/postgres`. The script creates and drops only databases named `factory_t_*` and `factory_tpl_*`. Use this in CI with a service container. **Do not point it at a server that matters.** The tests create the cluster-wide role `factory_app`, create and drop test roles, and switch superuser-only session settings. The script leaves `factory_app` behind on purpose.
2. A private local cluster. The script looks for `initdb`, `pg_ctl` and `postgres` in `FACTORY_PG_BIN`, on `PATH`, and in the usual Homebrew and Debian directories. It starts a cluster on a unix socket in a mode 0700 directory, with TCP off and `fsync` off, and stops and deletes it at the end.
3. Docker, with the image in `FACTORY_DB_IMAGE` (default `postgres:18`), published on a random loopback port with a random password.

`FACTORY_DB_PROVISION=local`, `docker` or `none` forces one of them or turns provisioning off. `FACTORY_DB_LEASE_ROUNDS` (default 25) sets how many contested claims the lease suite makes.

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
| `scripts/db-test.sh migrations` | Up, revert all, up again and redo on an empty database; the catalog is identical afterwards; the committed `schema.rs` equals `diesel print-schema`. |
| `scripts/db-test.sh statuses` | An unknown status is rejected on every status column; the allowed values equal `state-machine.json`. |
| `scripts/db-test.sh ledger` | `UPDATE` and `DELETE` on the ledger fail for the application role, and a gapped insert fails. |
| `scripts/db-test.sh tenancy` | A foreign key into another tenant's row is rejected, and unique keys include the tenant. |
| `scripts/db-test.sh terminal_rows` | `UPDATE` of a terminal stage run fails except for the supersede transition. |
| `scripts/db-test.sh plans` | The claim, sweep, timeline and ledger-tail queries use index scans on 10,000 generated rows. |
| `scripts/db-test.sh audit` | The application role can only `INSERT` and `SELECT` on the audit table (NT-AUD-01). |
| `scripts/db-test.sh webhook_delivery` | A second delivery with the same id violates a unique constraint and creates no second job or outbox row. |

Six more suites go beyond the criteria: `lease`, `outbox`, `approvals`, `tokens`, `privileges` and `contracts`.

## Regenerate `schema.rs`

1. Run `scripts/db-test.sh write-schema`. It migrates a throwaway database and writes the output of `diesel print-schema` to `crates/storage/src/schema.rs`.
2. Commit the file with the migration that caused the change. Never edit it by hand: the `migrations` suite compares it with a fresh `print-schema`.

## Expected output

A passing run ends like this (the number of checks changes when a test is added):

```text
PASS: migrations statuses ledger tenancy terminal_rows plans audit webhook_delivery lease outbox approvals tokens privileges contracts (510 checks, PostgreSQL 18.6 (Debian 18.6-1.pgdg13+2), docker)
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
| `role "factory_app" already exists` with other attributes | The migration refuses a role with superuser, create-role, create-database, replication or bypass-RLS rights. Fix the role. |

## Results of the runs for this work package

| Provider | PostgreSQL | Command | Result |
|---|---|---|---|
| Local cluster (Homebrew) | 18.6 | `scripts/db-test.sh`, twice in a row | pass both times, 510 checks, about 15 seconds each |
| Local cluster, persistent server | 18.6 | `FACTORY_DB_ADMIN_URL=... scripts/db-test.sh`, twice in a row | pass both times, no test database left, only the `factory_app` role remains |
| Docker `postgres:18` | 18.6 (Debian) | `FACTORY_DB_PROVISION=docker scripts/db-test.sh` | pass, 510 checks, container removed |
| Docker `postgres:16-alpine` | 16.15 | `FACTORY_DB_PROVISION=docker FACTORY_DB_IMAGE=postgres:16-alpine scripts/db-test.sh` | pass, 510 checks, container removed |
| No database (`FACTORY_DB_PROVISION=none`), unreachable server, no Diesel CLI on `PATH` | | `scripts/db-test.sh ledger` | exit code 3 and `BLOCKED:` each time |
| Ten deliberate breaks of the schema, one at a time | 18.6 | each break plus the suites that should notice it | exit code 1 each time, with a message naming the broken rule |
