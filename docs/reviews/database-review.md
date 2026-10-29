# Database review: queries, indexes, retention and compatibility at realistic volume

- Work package: `s1-database-review` (size M, owner dba, reviewer software_architect).
- Date: 2026-10-28. Reviewer of this document: not yet; an independent review follows. I do not certify my own work.
- Scope: the hot queries of the storage crate at 100,000 rows in each hot table with row-level security forced, as the three real logins; a retention and partitioning proposal for the outbox, the ledger and the artifact metadata; version N-1 code on version N schema; pool sizing, timeouts, statistics, autovacuum, bloat and backup coverage.
- Everything here was measured on one macOS laptop, PostgreSQL 18.6, client and server on the same machine. **The numbers are relative. They are not capacity claims.**
- The detail is in [docs/database/performance.md](../database/performance.md), [retention-and-partitioning.md](../database/retention-and-partitioning.md), [operating-settings.md](../database/operating-settings.md), [adr-0012-open-items.md](../database/adr-0012-open-items.md) and [migration-safety.md](../database/migration-safety.md). The harness is `scripts/db-perf.sh`; the machine-readable report of the run quoted here is [docs/database/perf-report-2026-10-28.json](../database/perf-report-2026-10-28.json).

## 1. Verdict

At 100,000 rows in each hot table, with row-level security forced, as the three real logins, **every measured query is inside its budget and none uses a sequential scan of a large table**, the claim path included. Row-level security costs about 2 microseconds per statement, plus the two round trips that set the tenant and the limits at the start of each transaction (51 microseconds on loopback). The review found **one thing worth a migration** (the lease renewal could never be a heap-only update; fixed by migration 19, with a test written first), **one scale limit that is not a defect but needs a decision** (the claim slows in proportion to READY runs of paused jobs), and **a handful of operating gaps** (no idle-transaction timeout, no statistics after a restore, no `pg_stat_statements` as deployed). Version N-1 code runs on every schema from 14 to 19. The retention and partitioning proposal says that nothing should be partitioned or deleted in Slice 1, and why the append-only design makes the later archive harder than it looks.

I did not certify this. An independent review follows.

## 2. The four done criteria of the package

| # | Criterion | Result | Evidence |
|---|---|---|---|
| 1 | Plans for claim, sweep, timeline and ledger tail at 100,000 rows are recorded, and none uses a sequential scan on the claim path | **Met** | `scripts/db-test.sh plans --rows 100000`: PASS, 43 checks (2026-10-28). Plans in [query-plans.md](../database/query-plans.md). The harness checks it again with a sequential-scan rule at 5,000 rows and shows it failing when the claim index is dropped (section 9). |
| 2 | Retention and partitioning proposals exist for the outbox, ledger and artifact metadata | **Met, as a proposal to review** | [retention-and-partitioning.md](../database/retention-and-partitioning.md), with prototypes that ran (`scripts/db-perf.sh --prototype partitions`). Five decisions for a person. |
| 3 | Each migration added in Slice 1 works with the previous code version | **Met for 15 to 19; not applicable or by design for 10 to 14** | `scripts/db-test.sh compat`: PASS, migrations 15 to 19 one at a time, with a control. `scripts/db-compat-rust.sh`: the real earlier storage crate, 49 tests at the control, the same 48 pass at each of 15 to 19; the 49th fails for a reason that proves the rule (section 8). |
| 4 | The cost of row-level security is measured at 100,000 rows (the extra statement per transaction, the claim and sweep plans) and recorded, and the result of each item ADR 0012 listed as not verified is in docs/database | **Met, one item not verifiable here** | [performance.md](../database/performance.md) section 2; [adr-0012-open-items.md](../database/adr-0012-open-items.md): four of the five items checked, the transaction-mode pooler not run. |

## 3. What was done, in order

| Increment | State |
|---|---|
| 1. A reproducible measurement harness (`scripts/db-perf.sh`): scratch cluster on 127.0.0.1, 18 migrations, deterministic skewed data with valid chains, the hot statements timed as the real logins with `EXPLAIN (ANALYZE, BUFFERS)`, p50 and p95, warm and cold, a machine-readable report | **Done** |
| 2. Findings, and a migration where measurement justifies one | **Done**: migration 19; two decisions left open (F-01, F-03) |
| 3. Retention and partitioning proposal, with prototypes | **Done** as a proposal |
| 4. N-1 compatibility, the matrix and the rule | **Done**: SQL level for each migration pair, Rust level for the earlier release; the rule is in [migration-safety.md](../database/migration-safety.md) |
| 5. Pool sizing, timeouts, `pg_stat_statements`, autovacuum, bloat after churn, backup coverage | **Done** with two limits: the Docker restore drill was not run (Docker is not allowed to this package), and the pooler was not run |
| The three deliberate breaks | **Done**, each shown caught (section 9) |

## 4. The measurements

The full tables, with the cold p95, the cost of the policy per statement, the plans and the generic plans, are in [performance.md](../database/performance.md); the report is [perf-report-2026-10-28.json](../database/perf-report-2026-10-28.json). One run, one laptop; relative numbers. Rows are those the first sampled parameters returned.

| Query | Rows returned | p50 ms | p95 ms | Plan node | Index | Verdict |
|---|---:|---:|---:|---|---|---|
| `claim_candidates` | 10 | 0.12 | 0.23 | Limit | jobs_open_idx, stage_runs_claim_order_idx | PASS |
| `due_lease_expired` | 10 | 0.22 | 0.25 | Limit | attempts_deadline_idx | PASS |
| `due_deadline_passed` | 10 | 0.16 | 0.18 | Limit | attempts_deadline_idx | PASS |
| `due_teardown_passed` | 0 | 0.10 | 0.12 | Limit | attempts_teardown_idx | PASS |
| `outbox_relay_poll` | 100 | 0.15 | 0.22 | Limit | outbox_unpublished_idx | PASS |
| `job_get@big` | 1 | 0.14 | 0.22 | Result | jobs_tenant_id_id_execution_mode_key | PASS |
| `list_jobs_page@big` | 50 | 0.16 | 0.21 | Limit | jobs_listing_idx | PASS |
| `list_jobs_repo@big` | 5 | 0.13 | 0.15 | Limit | jobs_repository_listing_idx | PASS |
| `stage_runs_by_job@big` | 10 | 0.15 | 0.20 | Sort | stage_runs_tenant_id_job_id_stage_kind_run_number_key | PASS |
| `check_run_history@big` | 10 | 0.15 | 0.17 | Sort | attempts_tenant_id_job_id_stage_run_id_id_key | PASS |
| `gate_records_by_job@big` | 0 | 0.17 | 0.19 | Sort + Sort | stage_runs_tenant_id_job_id_stage_kind_run_number_key | PASS |
| `outbox_timeline@big` | 11 | 0.16 | 0.23 | Limit | outbox_job_timeline_idx | PASS |
| `ledger_timeline@big` | 6 | 0.19 | 0.31 | Result + Limit | jobs_tenant_id_id_execution_mode_key, ledger_entries_tenant_id_job_id_sequence_entry_hash_key | PASS |
| `ledger_tail@big` | 1 | 0.16 | 0.24 | Limit + Result | jobs_tenant_id_id_execution_mode_key, ledger_entries_tenant_id_job_id_sequence_entry_hash_key | PASS |
| `audit_timeline@big` | 8 | 0.14 | 0.20 | Limit | audit_events_job_idx | PASS |
| `audit_tail@big` | 1 | 0.12 | 0.46 | Limit | audit_events_tenant_id_sequence_hash_key | PASS |
| `artifact_lookup@big` | 1 | 0.15 | 2.28 | Result | artifacts_pkey | PASS |
| `artifact_consumers@big` | 2 | 0.13 | 0.17 | Result | stage_run_artifacts_hash_idx | PASS |
| `job_get@small` | 1 | 0.14 | 0.27 | Result | jobs_tenant_id_id_execution_mode_key | PASS |
| `list_jobs_page@small` | 45 | 0.15 | 0.34 | Limit | jobs_listing_idx | PASS |
| `list_jobs_repo@small` | 2 | 0.14 | 0.27 | Limit | jobs_repository_listing_idx | PASS |
| `stage_runs_by_job@small` | 10 | 0.15 | 0.20 | Sort | stage_runs_tenant_id_job_id_stage_kind_run_number_key | PASS |
| `check_run_history@small` | 6 | 0.14 | 0.17 | Sort | attempts_tenant_id_job_id_stage_run_id_id_key | PASS |
| `gate_records_by_job@small` | 0 | 0.17 | 0.20 | Sort + Sort | stage_runs_tenant_id_job_id_stage_kind_run_number_key | PASS |
| `outbox_timeline@small` | 10 | 0.16 | 0.18 | Limit | outbox_job_timeline_idx | PASS |
| `ledger_timeline@small` | 10 | 0.18 | 0.24 | Result + Limit | jobs_tenant_id_id_execution_mode_key, ledger_entries_tenant_id_job_id_sequence_entry_hash_key | PASS |
| `ledger_tail@small` | 1 | 0.17 | 0.33 | Limit + Result | jobs_tenant_id_id_execution_mode_key, ledger_entries_tenant_id_job_id_sequence_entry_hash_key | PASS |
| `audit_timeline@small` | 8 | 0.14 | 0.29 | Limit | audit_events_job_idx | PASS |
| `audit_tail@small` | 1 | 0.13 | 0.27 | Limit | audit_events_tenant_id_sequence_hash_key | PASS |
| `artifact_lookup@small` | 1 | 0.13 | 0.15 | Result | artifacts_pkey | PASS |
| `artifact_consumers@small` | 2 | 0.13 | 0.17 | Result | stage_run_artifacts_hash_idx | PASS |
| `ledger_tail@long` | 1 | 0.13 | 0.14 | Limit | ledger_entries_tenant_id_job_id_sequence_entry_hash_key | PASS |
| `ledger_timeline@long` | 100 | 0.42 | 0.56 | Limit | ledger_entries_tenant_id_job_id_sequence_entry_hash_key | PASS |
| `resolve_token` | 1 | 0.12 | 0.22 | Function Scan | (function) | PASS |
| `resolve_installation` | 1 | 0.11 | 0.13 | Function Scan | (function) | PASS |
| `start_attempt` (write) | - | 0.57 | 1.14 | statement sequence | - | PASS |
| `heartbeat` (write) | - | 0.20 | 0.26 | statement sequence | - | PASS |
| `append_ledger_entry` (write) | - | 0.54 | 1.25 | statement sequence | - | PASS |
| `enqueue_event` (write) | - | 0.33 | 1.37 | statement sequence | - | PASS |
| `index_artifact` (write) | - | 0.23 | 0.74 | statement sequence | - | PASS |
| `audit_append` (write) | - | 0.26 | 0.66 | statement sequence | - | PASS |

Budget: 5 ms p95 for a read or a finder, 8 ms for a 100-entry ledger read, 10 ms for `start_attempt` and the two small inserts, 15 ms for a ledger or audit append. They are my numbers (the repository states none), argued in performance.md, and need the architect's confirmation.

## 5. Findings

Severity is for a Slice 1 deployment. "Owner" is who should act.

| # | Finding | Severity | Evidence | Status |
|---|---|---|---|---|
| F-01 | **The claim slows with the READY runs of jobs that are not ACTIVE.** The claim reads READY runs oldest first and joins each to its job; a run of a paused job stays READY and is visited and dropped at every claim. With 5,000 such runs ahead of the queue the statement goes from 0.04 to 4.05 ms (p95 4.58, buffers 60 to 16,673, 0.8 microseconds per junk run). With a burst of 20,000 READY runs of active jobs behind it, p95 6.2 ms, over the budget. Sixteen finders do worse than four (292 against 629 claims a second, p95 70 ms), because they all walk the same junk. The plan never changes and never scans a table. | medium, a scale limit; nothing at Slice 1 volume (stages run in order, so a job normally has one READY run, and the junk is bounded by the number of paused, blocked or waiting jobs; I did not prove that bound from the state machine) | performance.md section 5 | **Open, decision for the architect.** Options: keep READY runs out of the pool when a job leaves ACTIVE (a state machine change); a `claimable` flag kept by a trigger and a partial index on it; or a monitor on the count of READY runs of non-ACTIVE jobs with an alert at 1,000. I measured; I did not change the claim, which is a protocol (ADR 0014). |
| F-02 | **A lease renewal could never be a heap-only update.** `attempts_lease_expiry_idx` is keyed on the column every renewal changes, so each renewal wrote an entry to six indexes and left a dead tuple in each. 0.00 percent heap-only; after 45 seconds at full rate the heap grew 43 percent and the indexes 47 percent, with 416,647 dead tuples. | medium at scale, low now (a few renewals a second); the hottest write of the factory | performance.md section 6; `lease` section 14 failed before the fix | **Fixed: migration 19.** 99.84 percent heap-only, 3,192 dead tuples, no growth, throughput up a sixth, the sweeper unchanged within noise (p95 0.76 to 0.45 ms). Cost: the sweeper now reads the live attempts and sorts them, so it follows the number of live attempts. |
| F-03 | **No timeout stops an idle transaction, and no role has a default limit.** The 30 s statement and 5 s lock timeouts are set per transaction by the storage crate and protect the waiter. A holder that stops keeps its row locks: a second session waited the full 5 s and failed; with `idle_in_transaction_session_timeout` on the role it went through after 1.5 s. `resolve_token`, `resolve_installation` and `schema_version` run on a bare connection with no limit at all. | low to medium (a hung worker blocks one job's rows until its connection dies) | operating-settings.md section 2 | **Open.** Role settings on the three logins, set where the logins are created (`scripts/lib/ops.sh`); the lookups in a short transaction (storage crate). Neither file is in this package. |
| F-04 | **A restore leaves the planner with no statistics.** `pg_stats` held 185 rows before, 0 after. The dump carries none, and neither `restore.sh` nor the drill runs `ANALYZE`. | low | operating-settings.md section 5 | **Open.** Add `ANALYZE` at the end of `scripts/restore.sh`. Effect on plans not measured. |
| F-05 | **`pg_stat_statements` is not available as deployed.** The image does not preload it. | low | `--check settings` | **Open**, for the SRE: a `command:` line and `CREATE EXTENSION`. |
| F-06 | **The audit chain serializes per tenant, hard.** The trigger holds an advisory lock on the tenant until the transaction ends. One tenant reaches 2,300 to 4,600 events a second; if the transaction stays open 20 ms after the insert, the whole tenant is limited to 44 a second. | info; fine at Slice 1 volume; a trap for a transaction that writes the audit event early | performance.md section 4 | The rule "write the audit event last" is documented in ledger-and-audit.md; I did not trace every call site of `record_audit` (two in `crates/workflow`). A test that asserts it would be cheap. |
| F-07 | **The outbox update on publishing is never heap-only and doubles the heap until vacuumed.** `published_at` is in the predicate of the partial index the event leaves. | info | operating-settings.md section 4 | Resolved by pruning (retention proposal), not by tuning. |
| F-08 | **25 foreign keys have no index that starts with their columns.** Harmless today: no row is deleted and no key updated. | info now; a cost of retention later | performance.md section 7 | Not added. They become necessary before a job, a run or an artifact can be deleted or archived. |
| F-09 | **Retention and archive are blocked by the append-only design itself.** The ledger's link to the predecessor and the job's head are foreign keys, and a partition that holds referenced rows cannot be detached while they exist; the guard function is typed on the table's row type; `UNIQUE (tenant_id, entry_id)` cannot exist on a table partitioned by job. The outbox cannot be partitioned by time without weakening its keys. And ADR 0004 calls the outbox "the long-term record". | decision, not a defect | retention-and-partitioning.md sections 4 and 6 | Five decisions (D1 to D5) listed. |
| F-10 | **The one test that simulates "schema behind the code" stops working once the schema is ahead.** `tenant_isolation::refuses_a_role_that_bypasses_rls` deletes the newest migration row; with a schema newer than the code that row is not one the code lists. It failed for the earlier code at every schema from 15 on (the code started, correctly). It passes at HEAD only because code and schema both have 19. | low | migration-safety.md, the matrix | **Reported**, not changed (`crates/storage/tests` is another package's). |
| F-11 | **The upgrade test jumped from 14 to the newest in one step**, which cannot say which migration broke the earlier code. | process | | **Fixed:** the `compat` suite, one step at a time. |
| F-12 | **The extra statements per transaction.** Two round trips before the transaction's own; one would do. | info | performance.md section 2 | 24 microseconds saved on loopback, 0.3 to 1 ms over a network. A change in `tx.rs`. |

### What I looked for and did not find

- A query that uses a sequential scan of a large table, at either size, as any of the three logins: none.
- A policy expression that is evaluated per row or defeats an index: none. It is a one-time filter, or an index condition on the leading column.
- Contention of the hash chain across a tenant: none for the ledger (the chain is per job); the per-tenant lock of the audit log is the intended design and F-06.
- A duplicate publication by concurrent relays: none (0 in 66,100 publications at 1, 4 and 16 relays).
- An incompatibility between the earlier code and any of migrations 15 to 19: none.
- A hash chain that no longer verifies after the write, restore or partition tests: none (712,325 ledger entries and 495,761 audit events verified after the write tests; the restored database verifies).

## 6. Migrations added

| # | Name | Why | Test | Numbers |
|---|---|---|---|---|
| 19 | `2026-10-28-001900_lease_renewal_is_heap_only`: `DROP INDEX attempts_lease_expiry_idx` (down: create it again) | F-02 | `lease` section 14, written first and red (`expected 1, got 0`); the `plans` suite now accepts the new sweep plan and still fails on a sequential scan; the `migrations` suite (up, down, redo, catalog fingerprint, `schema.rs`); `compat` (the earlier code runs after it) | 0.00 to 99.84 percent heap-only; dead tuples 416,647 to 3,192; sweeper p95 0.76 to 0.45 ms |

No other schema change is justified by a measurement, and none was made. In particular: no index was added for the 25 unindexed foreign keys; the ledger's two indexes on `(tenant_id, job_id, sequence, ...)` were kept because the job's head and the link to the predecessor reference the wider one; the claim was not changed (F-01).

## 7. Retention and partitioning, in short

Nothing is partitioned or deleted in Slice 1. At about 400 KB per completed job (estimate), 10,000 jobs are 4 GB and 100,000 are 41 GB; three tables hold 83 percent of it. The outbox, when needed, is pruned by a role that can only delete published rows older than a retention period, not partitioned (the keys forbid it). The ledger can be partitioned by range of `job_id` (job ids are time ordered, a chain stays in one partition), but only after the unique key, the guard function and the two foreign keys that point into the ledger are changed; each obstacle was demonstrated. The audit log can be cut only by sequence range per tenant, with a checkpoint table and a verifier that starts from a checkpoint. A grant on a partition bypasses the parent's policy unless the partition has its own (shown). Artifact metadata is 5 percent of the bytes: do not partition; collect blobs by hash with a grace period. The full proposal, the triggers for acting and the decisions D1 to D5 are in [retention-and-partitioning.md](../database/retention-and-partitioning.md).

## 8. Version N-1 code on version N schema

Earlier code = the code written for the schema after migration 14. Two checks.

- **SQL, one migration at a time** (`scripts/db-test.sh compat`, PASS): schema 14 with a row in every table; migrations 15, 16, 17, 18, 19 applied in turn; after each, every row unchanged over its old columns and the earlier statements (claim, renewal, head move with a version bump, raised budget, timeline reads) still run.
- **The real earlier storage crate** (`scripts/db-compat-rust.sh`, revision `53c0938`, built offline, 11 test binaries run as the three real logins):

| Test binary | schema 14 (control) | 15 | 16 | 17 | 18 | 19 |
|---|---|---|---|---|---|---|
| `artifact_fs` | pass (14) | pass (14) | pass (14) | pass (14) | pass (14) | pass (14) |
| `artifact_scope` | pass (3) | pass (3) | pass (3) | pass (3) | pass (3) | pass (3) |
| `atomicity` | pass (3) | pass (3) | pass (3) | pass (3) | pass (3) | pass (3) |
| `audit` | pass (1) | pass (1) | pass (1) | pass (1) | pass (1) | pass (1) |
| `claims_and_leases` | pass (13) | pass (13) | pass (13) | pass (13) | pass (13) | pass (13) |
| `errors` | pass (2) | pass (2) | pass (2) | pass (2) | pass (2) | pass (2) |
| `ledger_chain` | pass (4) | pass (4) | pass (4) | pass (4) | pass (4) | pass (4) |
| `lookups` | pass (2) | pass (2) | pass (2) | pass (2) | pass (2) | pass (2) |
| `store_contract` | pass (1) | pass (1) | pass (1) | pass (1) | pass (1) | pass (1) |
| `tenant_isolation` | pass (6) | 5 of 6 | 5 of 6 | 5 of 6 | 5 of 6 | 5 of 6 |

The one failing test is F-10: a simulation that deletes the newest migration row to make the schema "behind", which stops meaning that once the schema is ahead. The code under test behaved as the rule says: it started on a schema newer than the one it was built for.

| Migration | Compatible in one step | Needs two steps |
|---|---|---|
| 10, 11 | yes (additive), no earlier code existed to run | |
| 12, 13, 14 (row-level security) | no, by design: code that does not set `factory.tenant_id` sees no row. Safe order: ship the code that sets it first | coordinated, not expand/contract |
| 15, 16, 17, 18, 19 | **yes**, SQL and Rust | none |

The rule for future migrations (add or relax in one step; anything else in two; the exception; how the baseline moves at each release; the Rust runner) is in [migration-safety.md](../database/migration-safety.md).

## 9. Deliberate breaks, each shown caught

| Break | Caught by | Result |
|---|---|---|
| Drop an index the harness depends on (`stage_runs_claim_order_idx`) | the verdict of `claim_candidates` | FAIL, exit 1: p50 4.80 ms (was 0.14), p95 5.99 ms over the 5 ms budget, sequential scan of `stage_runs` (100,000 rows) |
| Measure as a superuser | the guard statement of every session, and the identity check | REFUSED, exit 4, no number reported |
| Damage one ledger document in the synthetic data | the chain verification before the first measurement | REFUSED, exit 4, names the job and sequence 3 |
| The code stops sending a statement the harness repeats | `source_drift()` | exit 4 before measuring; unit-tested |
| A migration that renames a column the earlier code uses | the `compat` suite | FAIL: rows changed over the old columns, and the earlier renewal fails with `column "last_heartbeat_at" of relation "attempts" does not exist` |
| The renewal is not heap-only | `lease` section 14, before migration 19 | `expected 1, got 0` |

## 10. Pool sizing, timeouts, statistics, vacuum, bloat, backups

| Item | Finding | Section |
|---|---|---|
| Pools against `max_connections` | One API (8) and one worker (8 + 4) use 20 of 97 usable connections; one API and up to 7 workers fill the server. Eight is generous for a transaction of 0.1 to 1 ms. | operating-settings.md 1 |
| `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout` per role | 0, 0, 0 on every login. The first two are set per transaction by the storage crate (30 s, 5 s); the third nowhere; the three lookups have none. | 2; F-03 |
| `pg_stat_statements` | Not loaded by the image; `SELECT` fails with `must be loaded via "shared_preload_libraries"`. | 3; F-05 |
| Autovacuum | PostgreSQL defaults, no table setting. Trigger for a 100,000 row table: 20,050 dead tuples. Enough at Slice 1 and 2 volume; set `outbox` to 0.02 past a million rows. | 4 |
| Bloat after churn | 416,647 dead tuples and +43 percent heap in 45 seconds before migration 19; 3,192 and +0.8 percent in 90 seconds after. A vacuum reuses space and does not return it to the file system. | 4.1; F-02 |
| Backups cover what the schema holds | A dump taken as `backup.sh` takes it restores to a database with the same rows (22 of 22 tables), the same catalog except the parenthesisation of one `CHECK`, the same triggers, policies and grants, working isolation through a real login, and every chain verifying. Gaps: no statistics (F-04), no point-in-time recovery, the Docker drill not run here. | 5 |

## 11. What I could not verify, and why

- **Capacity.** One laptop, the client on the same machine, loopback, a warm file cache, a freshly loaded and vacuumed database. The numbers compare one query with another and one run with the next. They say nothing about jobs per second on a server.
- **A network.** A round trip is 25 microseconds here and 0.3 to 1 ms across a network, 12 to 40 times as much. The write paths (4 to 9 round trips each) and the two settings statements of F-12 grow in proportion; the per-statement times in the report let you do that sum.
- **The synthetic shape.** Ten stage runs, ten ledger entries, ten audit events and ten outbox events per job, 1.2 KB ledger documents, 50 tenants with one big one. These are my choices. The per-job estimate used for growth (386 rows, 403 KB, a 14-stage pipeline with rework) is an estimate from the state machine; the engine was not run to count real rows.
- **Tables the synthetic data leaves empty:** `approvals`, `original_requests`, `webhook_deliveries`, `task_nodes`, `task_node_dependencies`. Their queries (`valid_approvals`, the duplicate probe, the task graph reads) were not timed. The `plans` suite records their plans at 100,000 rows with data of its own.
- **The Rust Store under concurrency.** `pgbench` and `psql` stood in for the tokio runtime and the pool, with the statements copied from the code. The two appends in the concurrency runs compute the hash in a SQL function; the Store computes it in Rust.
- **Hardware and versions.** PostgreSQL 18.6 only. 16 and 17 were not run. No more than 16 clients.
- **The Docker restore drill and `backup.sh`.** Docker is not allowed to this package. The round trip used the same `pg_dump` and `pg_restore` options on a scratch cluster. The artifact files, the secret files and the password logins are the drill's.
- **A transaction-mode pooler.** None installed or planned.
- **The earlier release in full.** The Rust N-1 run covers the storage crate only, not the workflow or the worker, and one revision of it.
- **The engine's call sites.** Whether every transaction writes its audit event last (F-06) was not traced.
- **Partitions at size.** The prototypes ran at 30,000 rows. Not tried: hundreds of partitions, the cost of detaching a partition of gigabytes, replication of a partitioned table.
- **Cold.** "Cold" is a restarted server and a fresh backend, not a cold disk.

## 12. What this unblocks

- `s1-docs-and-walkthrough` depends on this package and can describe the database operations, the compatibility rule and the retention position.
- The Slice 2 load tests that ADR 0004 asked retention and partitioning to precede: the harness is the load baseline (re-run it at 10 times the rows), the proposal says nothing needs partitioning first, and the decisions D1 to D5 are the list to settle before they start.
- The next migration author has a rule and a check (`compat`) instead of a convention.
- The storage package has three concrete, measured changes to make or reject: one statement for the three transaction settings, the lookups inside a short transaction, and a fix for the one test that simulates a schema behind the code.
