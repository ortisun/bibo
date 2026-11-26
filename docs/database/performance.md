# Measured performance of the hot queries, at 100,000 rows, with row-level security on

- Status: measured on 2026-10-28 by the harness `scripts/db-perf.sh` (work package `s1-database-review`), PostgreSQL 18.6 (Homebrew), one macOS laptop, every number from one run unless a table says it is the median of three. Not yet reviewed by the software architect.
- Form: reference, with the method as explanation.
- Read this with: [query-plans.md](query-plans.md) (the plan shapes and the `plans` suite), [retention-and-partitioning.md](retention-and-partitioning.md), [operating-settings.md](operating-settings.md), and the review [../reviews/database-review.md](../reviews/database-review.md) that lists the findings.
- What these numbers are not: capacity claims. The server and the clients share one machine, the data sits in the operating system's file cache, the disk is a laptop disk, and the load is synthetic. Use them to compare one query with another, one plan with another, and one run with the next run of the same harness. Do not use them to say how many jobs per second a deployment can serve.

## Run it

```bash
scripts/db-perf.sh                                   # 100,000 rows in each hot table, about 25 minutes
scripts/db-perf.sh --rows 20000 --quick              # a smoke run, about 2 minutes
scripts/db-perf.sh --report r.json --markdown r.md   # the machine-readable report and the table
scripts/db-perf.sh --prototype partitions            # the partitioning prototypes (retention-and-partitioning.md)
scripts/db-perf.sh --check settings                  # the server as deployed: timeouts, extensions, an idle transaction that holds a lock
scripts/db-perf.sh --check backup                    # a dump and restore round trip, compared by catalog fingerprint
scripts/db-perf.sh --check frame                     # what the statements before a transaction's own cost, variants interleaved
python3 -I scripts/db-perf/test_perf.py              # unit tests of the pure parts (17 tests, no database)
```

It needs `initdb`, `pg_ctl`, `postgres`, `psql`, `pgbench` (a Homebrew or Debian PostgreSQL 17 or 18) and Python 3. It starts a cluster of its own on `127.0.0.1` at a random high port with no unix socket and SCRAM passwords made at run time, and removes it at the end, also on Ctrl-C. It never connects to any other database. No Docker.

Exit codes: 0 every verdict passed, 1 a verdict failed, 2 bad usage, 3 BLOCKED, 4 REFUSED.

## What it does

1. **Provisions.** Applies the 18 migrations as the superuser, creates the three logins the deployment creates (`perfdb_worker` in `factory_app`, `perfdb_api` in `factory_app` and `factory_resolver`, `perfdb_engine` in `factory_system`), and loads the data of [scripts/db-perf/load.sql](../../scripts/db-perf/load.sql).
2. **The data.** Deterministic: no random function, every identifier and size is a function of a counter, so two runs make the same rows. 50 tenants of skewed size (one holds 55 percent of the 10,000 jobs, four hold 5 percent each, 45 hold about 0.55 percent each). Each job has ten stage runs. 90 percent of the jobs are completed, 8 percent active (one READY run and one RUNNING run with a live attempt), 1 percent paused (a READY run that must not be claimed), 1 percent failed. `stage_runs`, `attempts`, `ledger_entries`, `outbox`, `audit_events` and `artifacts` each hold at least 100,000 rows. One attempt in ten holds a lease that expired five minutes ago and one in seven is past its deadline, so the sweeps have something to find; 6 percent of the finished runs needed a second attempt. Every ledger chain and every audit chain is written through the real triggers, so the hashes are the database's own, and the harness verifies all of them before it measures anything. Twenty jobs have a 200 entry ledger chain, for the long-job case. Payloads have realistic sizes: about 1.2 KB of canonical JSON per ledger entry, about 400 bytes of JSON per outbox event.
3. **Measures as the real login.** Before any number is taken the harness proves, for each login, that it is not a superuser, does not bypass row-level security, owns no table and belongs to exactly the groups the design gives it, and that every table with a tenant column has row-level security enabled **and forced**. Each measured session also runs a guard statement that divides by zero if the session is a superuser or bypasses the policies, so a number cannot come from a session that is not the login.
4. **Times the statements the storage crate sends.** One transaction in the shape `Store::begin` gives it: `BEGIN`, `SELECT set_config('factory.tenant_id', $1, true)`, `SELECT set_config('statement_timeout' ...), set_config('lock_timeout' ...)`, the statement or statements, `COMMIT`. The statements are copied from the Rust source (the file and function are in the `rust` field of the report), sent with named prepared statements over the extended protocol, as the crate sends them. The time of each command comes from `psql`'s own `\timing`, which includes the loopback round trip. 1,000 warm iterations (after 30 discarded) over parameters drawn from 400 jobs of a big tenant and 400 of small tenants; 60 cold-ish iterations right after a server restart (the operating system's file cache stays warm). If the Rust source no longer contains a statement the harness repeats, the harness refuses to run (exit 4), because its numbers would describe a query that is not sent. `python3 -I scripts/db-perf/test_perf.py` tests that check.
5. **Plans.** `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` of every statement as the login, parsed for the nodes, the indexes, the sequential scans, the rows removed by a filter, the buffers and whether the policy appears in the plan.
6. **Prices row-level security.** The tenant series again with `ALTER TABLE ... DISABLE ROW LEVEL SECURITY` on every policy table (the superuser does it; the data and the grants stay), then enabled again and re-proved by the identity checks.
7. **Write paths and concurrency**, on a clone of the database: the statement sequences of `start_attempt`, the heartbeat, the ledger append, the outbox insert, the artifact index insert and the audit append, committed (so the deferred triggers run); `pgbench` runs of appends on one job and on sixteen, audit appends on one tenant and on sixteen, claim finders, outbox relays that drain a backlog, a sweeper next to heartbeating workers. Each `pgbench` scenario is run three times and the run with the median throughput is reported.
8. **Churn.** Four clients renew leases for 90 seconds, then for 45 seconds with the index that migration 19 dropped put back; heap and index size, dead tuples, heap-only updates, autovacuum.
9. **Checks the structure.** Foreign keys with no index that starts with their columns.

## The budget

The repository states no latency budget for the database. These are mine, proposed for the architect to confirm or change.

| Path | Budget (p95 of the whole transaction, client side, at 100,000 rows) | Why this number |
|---|---|---|
| A read or a finder (one statement) | 5 ms | A stage runs for seconds to minutes. The engine polls at an interval of the same order. A call that takes 5 ms is invisible next to either, and a sequential scan of a 100,000 row table (about 5 ms and growing with the table) is not. The budget exists to catch that regression, and the harness shows it does (the dropped index below). |
| A read of a 200 entry ledger chain | 8 ms | About 120 KB leaves the database. |
| `start_attempt`, `enqueue_event`, `index_artifact` | 10 ms | Four to six statements, a deferred trigger at commit. |
| Ledger or audit append | 15 ms | The trigger parses the document and hashes it, and takes a lock. |

A verdict also fails when the plan scans a table of more than 5,000 rows sequentially (the done criterion says none on the claim path may; `jobs` holds 10,000 rows at the 100,000 row size, so a sequential scan of it would fail the claim). Below that size a hash join with a sequential scan of a small table is the right plan, and the plan suite accepts it too.

## What a number does and does not say

- The "whole transaction" time includes four round trips of the frame (`BEGIN`, two `set_config` statements, `COMMIT`). On this machine a round trip is about 30 microseconds. On a network with a 0.5 ms round trip the same transaction costs about 2 ms more, none of it in the database. The report keeps the per-statement times as well (`steps`).
- "Cold" means a freshly restarted server and a fresh backend, not a cold disk.
- The data is freshly loaded, vacuumed and analysed. A database that has run for a year has bloat, drifted statistics and a different cache. The churn run shows the first of these for the table that churns most.

## Results

The run: `scripts/db-perf.sh --rows 100000` on 2026-10-28, PostgreSQL 18.6 (Homebrew), macOS, the PostgreSQL defaults (`shared_buffers` 160 MB, `fsync` on, `synchronous_commit` on). Machine-readable report: [perf-report-2026-10-28.json](perf-report-2026-10-28.json) (without the index scan counts, which the churn run had reset). The data, as loaded:

| Table | Rows | Size with indexes | Bytes per row |
|---|---:|---:|---:|
| `ledger_entries` | 103,971 | 273 MB | 2,624 |
| `audit_events` | 100,000 | 168 MB | 1,677 |
| `outbox` | 109,000 | 125 MB | 1,148 |
| `stage_run_artifacts` | 179,700 | 72 MB | 401 |
| `attempts` | 101,292 | 60 MB | 590 |
| `stage_runs` | 100,000 | 53 MB | 528 |
| `artifacts` | 104,800 | 37 MB | 353 |
| `jobs` | 10,000 | 15 MB | 1,543 |
| (database) | | 816 MB | |

Tenants: 50. The big one holds 5,519 jobs and 55,190 stage runs; two of the medium ones 460 and 517 jobs; the small ones 44 to 56. Every hash chain verified before the first number was taken (10,000 ledger chains, 50 audit chains), and again after the write tests had added 600,000 ledger entries and 400,000 audit events (712,325 and 495,761 rows).

### 1. The statements, as the real logins

One transaction each (`BEGIN`, set the tenant, set the limits, the statement, `COMMIT`), time of the whole transaction on the client. p50 and p95 are of 1,000 warm iterations; "cold p95" is of the first 60 after a server restart. The column "query p50 RLS on / off" is the time of the statement alone with the policies enabled and then disabled. Every plan is an index scan; none scans a table of more than 5,000 rows sequentially.

| Series | Login | p50 ms | p95 ms | cold p95 ms | query p50 RLS on / off ms | Budget ms | Plan root | Indexes | Verdict |
|---|---|---:|---:|---:|---:|---:|---|---|---|
| `claim_candidates` | engine | 0.12 | 0.23 | 0.48 | - | 5.0 | Limit | jobs_open_idx, stage_runs_claim_order_idx | PASS |
| `due_lease_expired` | engine | 0.22 | 0.25 | 0.39 | - | 5.0 | Limit | attempts_deadline_idx | PASS |
| `due_deadline_passed` | engine | 0.16 | 0.18 | 0.36 | - | 5.0 | Limit | attempts_deadline_idx | PASS |
| `due_teardown_passed` | engine | 0.10 | 0.12 | 0.24 | - | 5.0 | Limit | attempts_teardown_idx | PASS |
| `outbox_relay_poll` | engine | 0.15 | 0.22 | 0.38 | - | 5.0 | Limit | outbox_unpublished_idx | PASS |
| `job_get@big` | worker | 0.14 | 0.22 | 0.28 | 0.04 / 0.04 | 5.0 | Result | jobs_tenant_id_id_execution_mode_key | PASS |
| `list_jobs_page@big` | worker | 0.16 | 0.21 | 0.36 | 0.06 / 0.06 | 5.0 | Limit | jobs_listing_idx | PASS |
| `list_jobs_repo@big` | worker | 0.13 | 0.15 | 0.35 | 0.04 / 0.04 | 5.0 | Limit | jobs_repository_listing_idx | PASS |
| `stage_runs_by_job@big` | worker | 0.15 | 0.20 | 0.36 | 0.05 / 0.05 | 5.0 | Sort | stage_runs_tenant_id_job_id_stage_kind_run_number_key | PASS |
| `check_run_history@big` | worker | 0.15 | 0.17 | 0.33 | 0.05 / 0.05 | 5.0 | Sort | attempts_tenant_id_job_id_stage_run_id_id_key | PASS |
| `gate_records_by_job@big` | worker | 0.17 | 0.19 | 0.36 | 0.07 / 0.07 | 5.0 | Sort + Sort | stage_runs_tenant_id_job_id_stage_kind_run_number_key | PASS |
| `outbox_timeline@big` | worker | 0.16 | 0.23 | 0.34 | 0.06 / 0.06 | 5.0 | Limit | outbox_job_timeline_idx | PASS |
| `ledger_timeline@big` | worker | 0.19 | 0.31 | 0.39 | 0.08 / 0.08 | 5.0 | Result + Limit | jobs_tenant_id_id_execution_mode_key, ledger_entries_tenant_id_job_id_sequence_entry_hash_key | PASS |
| `ledger_tail@big` | worker | 0.16 | 0.24 | 0.34 | 0.07 / 0.06 | 5.0 | Limit + Result | jobs_tenant_id_id_execution_mode_key, ledger_entries_tenant_id_job_id_sequence_entry_hash_key | PASS |
| `audit_timeline@big` | worker | 0.14 | 0.20 | 0.29 | 0.04 / 0.04 | 5.0 | Limit | audit_events_job_idx | PASS |
| `audit_tail@big` | worker | 0.12 | 0.46 | 0.29 | 0.03 / 0.03 | 5.0 | Limit | audit_events_tenant_id_sequence_hash_key | PASS |
| `artifact_lookup@big` | worker | 0.15 | 2.28 | 0.29 | 0.04 / 0.03 | 5.0 | Result | artifacts_pkey | PASS |
| `artifact_consumers@big` | worker | 0.13 | 0.17 | 0.35 | 0.03 / 0.03 | 5.0 | Result | stage_run_artifacts_hash_idx | PASS |
| `job_get@small` | worker | 0.14 | 0.27 | 0.40 | 0.04 / 0.03 | 5.0 | Result | jobs_tenant_id_id_execution_mode_key | PASS |
| `list_jobs_page@small` | worker | 0.15 | 0.34 | 0.45 | 0.05 / 0.05 | 5.0 | Limit | jobs_listing_idx | PASS |
| `list_jobs_repo@small` | worker | 0.14 | 0.27 | 0.40 | 0.04 / 0.04 | 5.0 | Limit | jobs_repository_listing_idx | PASS |
| `stage_runs_by_job@small` | worker | 0.15 | 0.20 | 0.39 | 0.05 / 0.05 | 5.0 | Sort | stage_runs_tenant_id_job_id_stage_kind_run_number_key | PASS |
| `check_run_history@small` | worker | 0.14 | 0.17 | 0.44 | 0.05 / 0.05 | 5.0 | Sort | attempts_tenant_id_job_id_stage_run_id_id_key | PASS |
| `gate_records_by_job@small` | worker | 0.17 | 0.20 | 0.57 | 0.07 / 0.07 | 5.0 | Sort + Sort | stage_runs_tenant_id_job_id_stage_kind_run_number_key | PASS |
| `outbox_timeline@small` | worker | 0.16 | 0.18 | 0.41 | 0.06 / 0.06 | 5.0 | Limit | outbox_job_timeline_idx | PASS |
| `ledger_timeline@small` | worker | 0.18 | 0.24 | 0.47 | 0.08 / 0.07 | 5.0 | Result + Limit | jobs_tenant_id_id_execution_mode_key, ledger_entries_tenant_id_job_id_sequence_entry_hash_key | PASS |
| `ledger_tail@small` | worker | 0.17 | 0.33 | 0.53 | 0.07 / 0.06 | 5.0 | Limit + Result | jobs_tenant_id_id_execution_mode_key, ledger_entries_tenant_id_job_id_sequence_entry_hash_key | PASS |
| `audit_timeline@small` | worker | 0.14 | 0.29 | 0.41 | 0.04 / 0.04 | 5.0 | Limit | audit_events_job_idx | PASS |
| `audit_tail@small` | worker | 0.13 | 0.27 | 0.38 | 0.03 / 0.03 | 5.0 | Limit | audit_events_tenant_id_sequence_hash_key | PASS |
| `artifact_lookup@small` | worker | 0.13 | 0.15 | 0.31 | 0.04 / 0.03 | 5.0 | Result | artifacts_pkey | PASS |
| `artifact_consumers@small` | worker | 0.13 | 0.17 | 0.31 | 0.04 / 0.03 | 5.0 | Result | stage_run_artifacts_hash_idx | PASS |
| `ledger_tail@long` (200 entries) | worker | 0.13 | 0.14 | 0.35 | 0.03 / 0.03 | 5.0 | Limit | ledger_entries_tenant_id_job_id_sequence_entry_hash_key | PASS |
| `ledger_timeline@long` (first 100 of 200, 120 KB) | worker | 0.42 | 0.56 | 0.54 | 0.18 / 0.21 | 8.0 | Limit | ledger_entries_tenant_id_job_id_sequence_entry_hash_key | PASS |
| `resolve_token` | api | 0.12 | 0.22 | 0.37 | - | 5.0 | Function Scan | (inside the function: api_tokens_token_hash_key) | PASS |
| `resolve_installation` | api | 0.11 | 0.13 | 0.27 | - | 5.0 | Function Scan | (inside the function: repositories_github_repository_id_key) | PASS |

The `audit_tail@big` and `artifact_lookup@big` p95 (0.46 and 2.28 ms) are single scheduling outliers among 1,000 iterations: in the first, undisturbed run of the same harness their p95 was 0.20 and 0.36 ms. Two other runs of the harness, made while other work was running on the machine, gave larger tails (up to 4.8 ms for the ledger timeline) and were discarded; the numbers above are from a run during which nothing else was started.

The ledger timeline and tail series run two statements, as `read_ledger` and `ledger_head` do: the job lookup, then the entries. For the single-statement series the report also holds the **generic plan**, the plan a prepared statement settles on after five executions (`plan_cache_mode = force_generic_plan`); it uses the same index as the custom plan in every one.

### 2. What row-level security costs

- **The policy.** The same 28 tenant series with every policy disabled: the median of the statement time is **0.049 ms with the policies and 0.046 ms without**; the median of the per-series differences is **2 microseconds**, the largest 7 microseconds, on statements that take 30 to 200. Nothing in the table is slower by more than the noise.
- **Why so little.** The policy is `tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid`. A query that names the tenant gets a **one-time filter** that compares the setting with the tenant once, before the scan. A query that forgets the tenant gets the expression **as the leading index condition**, so it is still an index scan of 3 buffers and returns only the session's tenant. A session with no setting does no index search and returns nothing. The system role's policies are `USING (true)`, which PostgreSQL drops from the plan: the claim plan as `factory_system` has no policy filter. The plans are quoted in [adr-0012-open-items.md](adr-0012-open-items.md).
- **The statements before the transaction's own.** A tenant transaction sends `set_config('factory.tenant_id', ...)` and a second `set_config` for the two timeouts before any statement of its own (`tx.rs`). Measured with the variants interleaved, 7 rounds of 3,000 transactions, loopback, median of the round medians:

  | Transaction | p50 ms | p95 ms |
  |---|---:|---:|
  | `BEGIN`, `SELECT 1`, `COMMIT` | 0.068 | 0.100 |
  | and one `set_config` for the tenant | 0.094 | 0.113 |
  | and a second `set_config` for the limits, as `Store::begin` sends them | 0.119 | 0.164 |
  | the tenant and the limits in **one** statement | 0.095 | 0.132 |

  Each round trip costs about **25 microseconds** here, so the two statements add 51 microseconds to a transaction that is 68 microseconds bare. One statement for all three settings would save 24 of them. The saving is the length of a round trip: 25 microseconds on loopback, 0.3 to 1 ms across a network. It is a change in `tx.rs` (the storage package's file), not made here.

### 3. The write paths

Committed on a clone, so the deferred triggers ran. Each is the sequence of statements the Store sends.

| Path | p50 ms | p95 ms | Budget ms | Verdict |
|---|---:|---:|---:|---|
| `start_attempt` (6 statements, job `FOR SHARE`, run `FOR NO KEY UPDATE`) | 0.57 | 1.14 | 10.0 | PASS |
| `heartbeat` (live attempt) | 0.20 | 0.26 | 5.0 | PASS |
| `append_ledger_entry` (lock the job, insert, move the head) | 0.54 | 1.25 | 15.0 | PASS |
| `enqueue_event` | 0.33 | 1.37 | 10.0 | PASS |
| `index_artifact` | 0.23 | 0.74 | 10.0 | PASS |
| `audit_append` | 0.26 | 0.66 | 15.0 | PASS |

### 4. Concurrency

Each scenario is `pgbench` with the given number of clients for 5 seconds, three times; the row is the run with the median throughput. Latency is of the whole transaction. The ledger and audit statements are issued through the application login under row-level security.

| Scenario | Clients | tps (three runs) | p50 ms | p95 ms | Failed |
|---|---:|---|---:|---:|---:|
| Ledger append, **one job** (the head of one chain) | 1 | 1,807 | 0.49 | 0.72 | 0 |
| | 4 | 2,635 (2,403 to 2,860) | 1.42 | 2.32 | 0 |
| | 16 | 2,157 (1,191 to 2,457) | 6.24 | 14.28 | 0 |
| Ledger append, 16 jobs of one tenant | 4 | 5,490 | 0.64 | 1.56 | 0 |
| | 16 | 11,812 | 1.06 | 2.86 | 0 |
| Ledger append, 16 tenants | 4 | 5,261 | 0.69 | 1.58 | 0 |
| | 16 | 11,730 | 1.02 | 2.44 | 0 |
| Audit append, **one tenant** | 4 | 4,644 | 0.75 | 1.45 | 0 |
| | 16 | 2,289 (1,534 to 3,452) | 5.83 | 13.73 | 0 |
| Audit append, 16 tenants | 4 | 8,808 | 0.33 | 1.45 | 0 |
| | 16 | 11,188 (7,411 to 13,249) | 0.79 | 3.87 | 0 |
| Audit append, one tenant, **transaction held 20 ms after the insert** | 4 | 45 | 88.55 | 92.47 | 0 |
| | 16 | 44 | 353.62 | 381.28 | 0 |
| Claim finders (`LIMIT 10`, `SKIP LOCKED`) | 1 | 7,348 | 0.12 | 0.24 | 0 |
| | 4 | 21,281 | 0.15 | 0.30 | 0 |
| | 16 | 22,792 | 0.67 | 1.01 | 0 |
| Claim finders holding their locks 5 ms | 1 | 151 | 6.67 | 7.69 | 0 |
| | 4 | 618 | 6.61 | 6.97 | 0 |
| | 16 | 2,489 | 6.59 | 6.95 | 0 |

What it shows:

- **Ledger chain head.** Appends to one job serialize on the job row (`FOR NO KEY UPDATE`): about 2,000 to 2,700 a second whatever the number of clients, and the p95 grows with the queue (14 ms at 16 clients). The chain is per job, not per tenant: 16 jobs of one tenant append at 11,800 a second, and 16 tenants at 11,700. A real job appends a few dozen entries over minutes, so one chain never nears its limit.
- **Audit chain.** The chain is per tenant and the trigger takes an advisory lock on the tenant, held until the transaction ends. One tenant tops out near 2,300 to 4,600 events a second; 16 tenants reach 8,800 to 11,200. Held for 20 ms after the insert, every writer of that tenant waits: **44 to 45 transactions a second for the whole tenant**, and a p95 of 92 ms at 4 writers and 381 ms at 16. This is what [ledger-and-audit.md](ledger-and-audit.md) says in words ("write audit events last"); here is the number. `pg_stat_statements` in the same run: `pg_advisory_xact_lock` took a mean of 1.34 ms of an insert that took 1.52 ms.
- **Claim finders.** `SKIP LOCKED` does its job: 16 finders do not slow each other beyond CPU (22,800 a second). With the locks held for 5 ms each, throughput follows the hold time, not the contention (151, 618, 2,489 for 1, 4, 16 finders: 150 per finder).
- **The 16 client rows have a wide spread** (the three runs of the audit scenario at 16 clients ran at 1,534, 2,289 and 3,452). With `fsync` on, commits are the limit, and the laptop's disk and its other work move it. Read the order of magnitude.

#### The outbox relay

A backlog of about 22,000 unpublished rows (every fifth row reset), drained by `WITH c AS (SELECT seq ... LIMIT 100 FOR NO KEY UPDATE SKIP LOCKED) UPDATE outbox ... FROM c` as the system login, `pgbench` with enough transactions to drain it with margin:

| Relays | Backlog | Wall s | Duplicate publishes | Left unpublished |
|---:|---:|---:|---:|---:|
| 1 | 22,300 | 5.33 | 0 | 0 |
| 4 | 21,900 | 1.54 | 0 | 0 |
| 16 | 21,900 | 0.81 | 0 | 0 |

`publish_attempts` never exceeded 1: no event was taken twice. The relay is not in the Rust crate yet; this is the statement from `docs/database/tests/outbox.sql` with a `LIMIT` and an update. The update that marks an event published is never heap-only (`published_at` is in the predicate of the partial index the event leaves), so each published event leaves a dead tuple: three drain cycles grew the heap from 89 to 125 MB until a vacuum ([operating-settings.md](operating-settings.md)).

#### The sweeper next to the workers

One sweeper (expired lease, `LIMIT 10`) alone: 2,408 transactions a second, p95 0.46 ms. Next to four clients renewing leases: the sweeper 2,176 a second (p95 0.54 ms) and the renewals 16,929 a second (p95 0.31 ms). They do not hurt each other.

### 5. The claim when the head of the queue is junk

The claim reads READY stage runs in `(not_before, id)` order and joins each to its job to keep those of `ACTIVE` jobs. A run of a `PAUSED` job stays READY. If many sit at the head of the order, each claim visits and drops all of them first.

| State of the queue | READY runs (of ACTIVE jobs) | Statement p50 ms | p95 ms | Buffers hit | Index |
|---|---:|---:|---:|---:|---|
| The data as loaded (a tenth of the READY runs are of paused jobs), after the write tests took 300 | 600 (500) | 0.04 | 0.06 | 60 | claim order index, `jobs_open_idx` |
| 5,000 more, **older than all others**, of paused jobs | 5,600 (500) | 4.05 | 4.58 | 16,673 | the same |
| and 20,000 READY runs of active jobs behind them | 25,600 (20,500) | 4.73 | 6.23 | 21,668 | the same |

The plan never changes and never scans a table: it is the same index scan, nested loop and memoized lookup, longer. The cost is about **0.8 microseconds for each junk run ahead of the queue**, which is 100 times the baseline at 5,000. Finders under that load, `pgbench`: 1 finder 149 a second (p95 15 ms), 4 finders 629 (p95 8.6 ms), **16 finders 292 a second (p95 70 ms)**: more finders do worse, because all of them walk the same junk and then queue for the same few rows. See finding F-01 in the [review](../reviews/database-review.md).

### 6. Churn: the lease renewal

`heartbeat` renews a lease. When this was measured the statement was `UPDATE attempts SET lease_expires_at = ..., last_heartbeat_at = now(), version = version + 1`; since [ADR 0038](../adr/0038-a-heartbeat-renews-the-lease-and-leaves-the-version.md) it no longer changes `version`, and the numbers below were not measured again. Four clients renew 200 live attempts at random as fast as they can, from a vacuumed table, the leases refreshed first. Same database, same machine, same PostgreSQL defaults; the "before" row has the index `attempts_lease_expiry_idx` put back.

| Schema | Renewals | per second | Heap-only (HOT) share | Dead tuples left | `attempts` heap, bytes | `attempts` indexes, bytes |
|---|---:|---:|---:|---:|---|---|
| Before migration 19 (index on the lease), 45 s | 492,609 | 10,946 | **0.0000** | **416,647** | 25,272,320 to 36,233,216 (+43%) | 35,250,176 to 51,789,824 (+47%) |
| Migration 19 (no index on the lease), 90 s | 1,154,376 | 12,827 | **0.9984** | **3,192** | 25,059,328 to 25,272,320 (+0.8%) | 35,201,024 to 35,209,216 (+0.02%) |

Before the migration not one renewal in ten thousand was heap-only, and each wrote an entry to six indexes. After it, 99.84 percent were, the heap grew by 0.2 MB in 1.15 million renewals, and the indexes did not grow. The throughput rose by a sixth. The sweeper that used the index: p95 0.76 ms with it, 0.45 ms without, both far under the budget (the plan before: an incremental sort over `attempts_lease_expiry_idx`; after: a scan of the live attempts through `attempts_deadline_idx` with a filter and a sort). With the PostgreSQL defaults autovacuum did not start during the 90 seconds after the migration (3,192 dead tuples is under the trigger of 20,050), and a `VACUUM` afterwards had nothing to reclaim.

The test that holds this: `lease` section 14 reads the transaction's own heap-only counter and fails if a renewal is not heap-only. It failed before the migration (`expected 1, got 0`) and passes after.

### 7. Structure

**Foreign keys with no index that starts with their columns: 25.** `approvals(tenant_id, job_id, stage_run_id)`, `approvals(tenant_id, approver_principal_id, ...)`, `artifacts(tenant_id, created_by_job_id, created_by_stage_run_id)`, `attempts(tenant_id, output_sha256)`, `audit_events(tenant_id, job_id, stage_run_id)`, `audit_events(tenant_id, prev_sequence, prev_hash)`, `jobs(tenant_id, id, ledger_head_sequence, ledger_head_hash)`, `jobs(tenant_id, normalized_request_sha256)`, `jobs(tenant_id, requester_principal_id)`, `ledger_entries(tenant_id, job_id, execution_mode)`, `ledger_entries(tenant_id, job_id, prev_sequence, prev_entry_hash)`, `ledger_entries(tenant_id, job_id, stage_run_id, attempt_id)`, `outbox(event_type, aggregate_type, transition_id)`, `repositories(tenant_id, bypass_attested_by_principal_id)`, `stage_run_artifacts(tenant_id, job_id, stage_run_id)`, `stage_runs(tenant_id, gate_report_sha256)`, `stage_runs(tenant_id, job_id, rework_of_stage_run_id)`, `stage_runs(tenant_id, stage_contract_sha256)`, the task node ones, and two on the reference tables. An unindexed foreign key costs nothing until a parent row is deleted or its key is updated: then PostgreSQL scans the child table for each one. **No row is deleted today and no key is updated, so none of them is a defect now.** They become the cost of the retention work: before a job, a stage run or an artifact can be deleted or archived, the foreign keys that point at it need an index, or the deletion scans the ledger and the audit log once per row. Not added, because an index written by every insert and read by nothing is a cost (the lesson of `task_node_dependencies` in query-plans.md).

**The statements that take the time, by `pg_stat_statements`** (the clone, all the scenarios; the read series ran on the other database): the audit insert (mean 1.52 ms under contention, of which the advisory lock 1.34 ms), `perf.append_next` (0.75 ms), the job lock in it (0.43 ms), the claim query (0.32 ms mean over 820,000 calls including the junk states), the renewal (0.07 ms over 1.7 million calls), the ledger insert (0.17 ms).

### 8. Deliberate breaks, shown caught

| Break | How | What the harness did |
|---|---|---|
| Drop the claim index | `--break drop-index=stage_runs_claim_order_idx`, 100,000 rows | `claim_candidates` **FAIL**: p50 4.80 ms (it was 0.14), p95 5.99 ms over the 5 ms budget, "sequential scan of stage_runs (100,000 rows); the claim path scans a table sequentially", exit 1 |
| Measure as a superuser | `--break superuser` | **REFUSED**, exit 4: "the session for series claim_candidates is postgres, which is a superuser or bypasses row-level security (the guard statement failed). No numbers are reported." |
| Break the hash chain | `--break chain`: one ledger document edited with triggers off | **REFUSED**, exit 4: "the synthetic data's hash chain does not verify (ledger: job ... sequence 3)" |
| The code stops sending a statement the harness repeats | unit test: a fragment that is not in `ledger.rs` | `source_drift()` returns it; the harness exits 4 before it measures (`python3 -I scripts/db-perf/test_perf.py`) |
| A migration that renames a column the earlier code uses | `compat` suite with an added migration | **FAIL** on both counts: rows changed over the old columns, and the earlier renewal fails (`column "last_heartbeat_at" of relation "attempts" does not exist`) |
| The lease renewal is not heap-only | the `lease` suite before migration 19 | `expected 1, got 0` |

### 9. What was not measured here

One client machine (the harness and the server share it); no network. No production-like disk. The OS file cache is warm in every "cold" figure. Data that has not aged: freshly loaded, vacuumed, analysed. The Rust Store's own concurrency (a tokio runtime, pool waits) was not driven; `pgbench` and `psql` stand in for it, with the statements copied from the code. The audit append and the ledger append were also driven through SQL functions in `pgbench` (the hash computed in the database), which adds a little to each. PostgreSQL 16 and 17 were not run. Sixteen clients is the top; there is no 64-client run.
