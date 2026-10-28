# Operating settings: connections, timeouts, statistics, vacuum, bloat and backups

- Status: checked 2026-10-28 by the work package `s1-database-review`, on PostgreSQL 18.6 started with its defaults (`scripts/db-perf.sh --check settings`, `--check backup`) and by reading the repository. Nothing here changes a setting; the recommendations are for the owners named in each section. Not yet reviewed by the software architect or the SRE.
- Form: reference, with recommendations marked as such.
- The server in `infra/compose/local.yml` is `postgres:18.6` with no `command:` line, so the defaults below are the deployed ones.

## 1. Connections

Where the numbers come from: `PoolSettings::new` (`crates/storage/src/pg/config.rs`) gives a pool 8 connections; the example configurations (`infra/compose/config/*.example.yaml`) set 8 for the API, 8 for the worker's tenant pool and 4 for its system pool.

| Process | Pool | Login | Connections |
|---|---|---|---:|
| API | tenant pool, which also serves the three lookups | `factory_api` | 8 |
| Worker | tenant pool | `factory_worker` | 8 |
| Worker | system pool | `factory_engine` | 4 |
| One API and one worker | | three logins | **20** |

`max_connections` is 100 and `superuser_reserved_connections` is 3, so **97 are usable**. The local stack uses 20 of them (21 percent). Each further worker process adds 12; each further API process adds 8. Keeping about 10 for the deploy step, a backup (`pg_dump` holds one), an operator's `psql` and the harness, the arithmetic is **one API and up to 7 workers** before the pools alone fill the server. Nothing in the repository checks this sum.

Is 8 the right size? The measurements say the pool is generous. A transaction occupies a connection for 0.1 to 1 ms of database time (the whole transaction, round trips included: p50 0.1 to 0.4 ms and p95 under 0.6 ms for 34 of the 35 series at 100,000 rows; [performance.md](performance.md)). One connection serves thousands of them a second, and the lock waits, not the pool, are what hold a connection longer: a ledger append to one job is serialized at about 1,800 to 2,700 per second whatever the number of clients. The size to worry about is the system pool: a claim cycle holds a connection while the engine does its follow-up work if the code keeps the system transaction open that long (the hold-for-5-ms rows in the concurrency table of performance.md show 151 transactions a second for one finder, because each holds its lock for 5 ms). The code documents that the system transaction only finds and then finishes, so 4 is enough.

Recommendation (SRE): put the sum in a start-up check or a runbook line, and prefer a smaller tenant pool (4) per worker if a second worker per machine is planned. No pooler (PgBouncer) is needed; the transaction-local tenant setting is compatible with transaction pooling in principle, but this was not run ([adr-0012-open-items.md](adr-0012-open-items.md)).

## 2. Timeouts

What each setting is today, as the three logins see it on a fresh connection (`SHOW`):

| Setting | `factory_worker` | `factory_api` | `factory_engine` |
|---|---|---|---|
| `statement_timeout` | 0 (off) | 0 | 0 |
| `lock_timeout` | 0 | 0 | 0 |
| `idle_in_transaction_session_timeout` | 0 | 0 | 0 |

No role or database default exists (`pg_db_role_setting` is empty). The only limits are those the storage crate sets per transaction with `set_config(..., true)` at the start of a tenant or system transaction: `statement_timeout` 30 s and `lock_timeout` 5 s (`tx.rs`, `system.rs`). Three consequences.

1. **The three lookups run without any limit.** `resolve_token`, `resolve_installation` and `schema_version` run on a bare pooled connection outside a transaction (`store.rs`), so neither limit applies. They are index lookups of 0.1 ms and take no row lock, so the risk is small; they are also the first thing an unauthenticated request reaches.
2. **Nothing ends an idle transaction.** The limits above protect a waiter from a slow holder. They do not stop a holder that stops. Measured (`--check settings`): one worker session takes `FOR NO KEY UPDATE` on a job row and then sits idle in its transaction; a second session asking for the same row waited 5.05 s and failed with the lock timeout. With `idle_in_transaction_session_timeout = '2s'` set on the role, the first session was ended by the server and the second one went through after 1.53 s. Without it a hung worker (a stopped process, a dead network path that TCP takes hours to notice) keeps the locks of its transaction for as long as the connection stays up. The lease sweeper recovers the attempt; it cannot release a lock held by a transaction.
3. **Anyone who connects some other way has no limits.** An operator's `psql`, the migration run, a script.

Recommendations (SRE, with the architect):

- `ALTER ROLE factory_worker, factory_engine, factory_api SET idle_in_transaction_session_timeout = '60s';` and a `statement_timeout` default (60 s) as a ceiling for what runs outside a `Tx`. They have to be set on the **login** roles: a setting on a group role (`factory_app`) is not inherited by its members. The logins are created by `scripts/lib/ops.sh`, which this package may not edit; the migrations create only the groups. A role setting is part of `pg_dumpall --globals-only`, so a restore keeps it (checked: the dump of the scratch cluster has no `ALTER ROLE ... SET` line today, because none exists).
- Run the three lookups inside a short transaction that sets the limits, like every other call. This is a storage-crate change.
- Choose 60 s for the idle limit only after checking the longest legitimate transaction. The engine documents that no `Tx` should wait on anything but the database; if one does, the number moves.

## 3. `pg_stat_statements`

**Not available as deployed.** The image does not preload it. Run on a default cluster: `SELECT count(*) FROM pg_stat_statements` answers `ERROR: pg_stat_statements must be loaded via "shared_preload_libraries"`. The extension files are present in the Debian image (the harness's own cluster preloads it and reports the top twelve statements by total time in its report, `pg_stat_statements_top`).

To enable: start the server with `-c shared_preload_libraries=pg_stat_statements -c pg_stat_statements.track=all -c track_io_timing=on` (a `command:` in `infra/compose/local.yml`, SRE's file) and run `CREATE EXTENSION pg_stat_statements` once as the superuser. A restart is needed. It stores normalized query text, not parameters, so it holds no tenant data; reading it needs `pg_read_all_stats` or the superuser. The tenant setting is sent as a bound parameter and never appears in a statement text.

What it would have shown in the harness run: with 16 clients appending audit events to one tenant, `pg_advisory_xact_lock(...)` took a mean of 1.28 ms of a 1.45 ms insert, which is the per-tenant serialization of [ledger-and-audit.md](ledger-and-audit.md) made visible.

## 4. Autovacuum and bloat

Defaults in force: `autovacuum` on, `autovacuum_naptime` 60 s, `autovacuum_vacuum_scale_factor` 0.2, `autovacuum_vacuum_threshold` 50, `autovacuum_vacuum_insert_scale_factor` 0.2, `autovacuum_analyze_scale_factor` 0.1, `autovacuum_max_workers` 3, `autovacuum_vacuum_cost_delay` 2 ms. No table sets a storage parameter (`reloptions` empty on every table).

The default trigger for a table of 100,000 rows is 50 + 0.2 x 100,000 = **20,050 dead tuples**. Which tables make dead tuples:

| Table | What makes dead tuples | Heap-only? | Result of the churn run |
|---|---|---|---|
| `attempts` | A renewal of a lease, every few seconds per live attempt | **Before migration 19: no.** The index keyed on `lease_expires_at` forbade it. **After: yes.** | See the table in section 4.1. |
| `outbox` | One update per event, when it is published (`published_at`, `publish_attempts`) | No: `published_at` is in the predicate of the partial index `outbox_unpublished_idx`, and the update makes the row leave that index | A relay that published 21,900 rows left 21,900 dead tuples and grew the heap from 89 MB to 125 MB (the update writes a whole new tuple of about 1.6 KB) until a vacuum |
| `stage_runs`, `jobs` | A few status changes per row over its life | No (status is in several partial indexes) | Not measured under load |
| `ledger_entries`, `audit_events` | None: append only | | |

### 4.1 Churn, measured

Four clients renewed 200 live attempts as fast as they could, from a vacuumed table (details and the first-hand numbers in [performance.md](performance.md), section 6):

| Schema | Renewals | Heap-only (HOT) share | Dead tuples left | `attempts` heap | `attempts` indexes |
|---|---:|---:|---:|---|---|
| Before migration 19 (an index keyed on the lease), 45 s | 492,609 | 0.0000 | 416,647 | +43% | +47% |
| Migration 19, 90 s | 1,154,376 | 0.9984 | 3,192 | +0.8% | +0.02% |

Autovacuum did not run in the 90 seconds after the migration: 3,192 dead tuples are under the trigger of 20,050. Before it, the trigger was crossed in the first second and then again every few seconds, and autovacuum would have been busy on the hottest table for as long as the workers ran. A vacuum frees the space for reuse; it does not give it back to the file system, so the 11 MB the heap grew in 45 seconds stays in the file until a `VACUUM FULL`. At realistic rates (a few renewals a second) the first row would be a slow version of the same thing.

The outbox is the other table that churns, once per event: publishing 21,900 events with a relay left 21,900 dead tuples and, over three drain cycles of 22,000 rows, grew the heap from 89 MB to 125 MB until vacuumed. It is not heap-only and cannot be, as long as `published_at` is in the predicate of the partial index the event leaves. The fix is to delete published events, not to tune vacuum ([retention-and-partitioning.md](retention-and-partitioning.md)).

Recommendations (SRE): the defaults are enough at the volumes of Slices 1 and 2. When `outbox` passes a million rows, give it `autovacuum_vacuum_scale_factor = 0.02` and `autovacuum_analyze_scale_factor = 0.02`, so a vacuum runs after 20,000 dead tuples, not 200,000. `fillfactor` would not help `attempts` (the updates it would make room for are now heap-only anyway, but the status changes are not and are rare) and is not proposed.

## 5. Backups and restore: do they hold everything the schema holds?

Method: `scripts/db-perf.sh --check backup` loads the synthetic data, takes the dump the way `scripts/backup.sh` takes it (`pg_dump --format=custom` of the database, `pg_dumpall --globals-only --no-role-passwords`), restores it into a second database with `pg_restore --exit-on-error --single-transaction`, and compares. The Docker-based drill (`scripts/restore-drill.sh`) was not run: this work package may not use Docker. The drill covers more (the artifact files, the secrets, the logins by password); this covers the schema.

Result of `scripts/db-perf.sh --check backup` (2026-10-28, 20,000 rows per hot table, a database of 170 MB):

| What the schema holds | In the catalog | In the dump (`pg_restore --list`) | Round trip |
|---|---:|---:|---|
| Tables | 22 (plus 2 of the harness's own `perf` schema) | 24 | every table has the same row count after the restore (22 compared) |
| Indexes not backing a constraint | 20 | 20 | |
| Primary and unique constraints | 47 (plus 2 of `perf`) | 49 | |
| Foreign keys | 53 | 53 | |
| `CHECK` constraints | 148 | inside the `CREATE TABLE` entries | |
| Triggers | 30 | 30 | the append-only, hash and guard triggers fire after the restore (an event inserted into the restored `outbox` passes `outbox_aggregate_check` and gets sequence 21,801 after 21,800) |
| Row-level security enabled and forced | 18 tables | 18 `ROW SECURITY` entries | tenant 1 reads 1,119 of 1,119 jobs through the worker login; tenant 2 sees none of them |
| Policies | 29 | 29 | |
| Functions | 38, of which 5 belong to an extension | 33 | |
| Views | 5, of which 2 belong to an extension | 3 | |
| Grants | | 106 `ACL` entries | the catalog fingerprint of the migrations suite (tables, columns, constraints, indexes, triggers, functions with owner and ACL, policies, grants of the four groups) is equal, except one line (below) |
| Sequence of the outbox identity | | `SEQUENCE SET` | continues where it stopped |
| Extensions | 2 | 2 | |
| Roles, memberships | 8 `CREATE ROLE`, 4 memberships | `globals.sql` | no password in the file; no role-level `SET` (none exists) |
| Hash chains | 20,787 ledger entries, 20,000 audit events | | all 2,000 ledger chains and all 50 audit chains verify on the restored database |

The dump of that database took 1.7 s (15 MB) and the restore 3.9 s. A straight line from there to the 41 GB of the 100,000 job projection in [retention-and-partitioning.md](retention-and-partitioning.md) is about 7 minutes to dump and 16 minutes to restore, a guess from a straight line (restore time is dominated by index builds and does not scale that way exactly).

Gaps found, none of them in the dump itself:

1. **No planner statistics after a restore.** `pg_stats` held 185 rows in the source and 0 in the restored database: the dump carries no statistics, and neither `restore.sh` nor the drill runs `ANALYZE`. Until autovacuum analyzes each table (it waits up to a minute and then works table by table), plans are chosen on defaults. Add `ANALYZE` (or `vacuumdb --analyze-in-stages`) to the end of `scripts/restore.sh`. Not changed here (the script is not in this package's paths). Whether the plans on an unanalyzed restore are bad was not measured.
2. **No point-in-time recovery.** `scripts/backup.sh` is a dump; the recovery point is the time of the last dump (`--keep 7`). There is no WAL archiving. A restore returns the ledger and the audit log to that moment; entries written after it are lost with no trace, and the external anchor that would reveal that does not exist ([not-covered.md](not-covered.md)).
3. **The dump is consistent, the pair is not atomic.** The artifact copy is taken after the dump (blobs are written before their rows), which is the right order, and the script refuses to run while the engine is connected unless told to.
4. **Roles.** The globals file holds 8 `CREATE ROLE` lines and 4 memberships and no password. If the recommendations of section 2 are adopted, the role settings travel with it.
5. **One restore-time difference.** The catalog fingerprint of the migrations suite differs between source and restored database in one line: the check `jobs_pipeline_scope_check` is printed with its nested `AND` flattened (`((a AND b) AND c)` becomes `(a AND b AND c)`). The condition is the same. A fingerprint comparison after a restore must tolerate it; the restore verification of `scripts/restore.sh` compares grants and policies, not constraint text, and is not affected.
