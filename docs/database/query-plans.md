# Query plans on 10,000 generated rows

- Status: recorded from `scripts/db-test.sh plans` on 2026-10-27, PostgreSQL 18.6 (Homebrew), one laptop, `EXPLAIN (COSTS OFF)`. The same suite passed on PostgreSQL 16.15 and on 18.6 in Docker. The plans are text from one run; the suite asserts only that the named index is used and that the large table is not scanned sequentially.
- Form: reference.
- Limits: this is the shape of the plans on a small, freshly analysed data set. It says nothing about timing, cache behaviour or bloat under load. The `s1-database-review` package measures those once there is a store to measure.

## The data

The suite builds the data inside the migrated schema, then runs `ANALYZE`.

| Table | Rows | Mix |
|---|---|---|
| `jobs` | 2,000 | 90% completed, 8% active, 1% paused, 1% failed. Five tenants. |
| `stage_runs` | 10,000 | 1.6% `READY` (160), 1.6% `RUNNING`, the rest `PASSED` or `PENDING`. |
| `attempts` | about 9,600 | Mostly finished. About 160 live, of which about one in ten has an expired lease, and about 8 are `CANCELLING`. |
| `ledger_entries` | 10,000 | 100 jobs with 100 valid hash-chained entries each, inserted through every trigger. |
| `outbox` | 10,000 | Five events per job. 99% published. |
| `audit_events` | 10,000 | Five tenants, valid chains. |
| `api_tokens`, `artifacts`, `stage_run_artifacts` | 200, 2,000, 2,000 | For the lookups by hash. |

Bulk status changes on `jobs`, `stage_runs`, `attempts` and `outbox` ran with triggers off, because they stand for months of earlier work. The ledger, audit and new outbox rows went through every trigger and constraint. That is why the suite can also check that the generated chains verify.

## The plans

| Query | Plan | Index used |
|---|---|---|
| **Claim**: `READY` runs of `ACTIVE` jobs, `ORDER BY not_before LIMIT 10 FOR NO KEY UPDATE SKIP LOCKED` | Index Scan on `stage_runs`, hash join to `jobs` (a sequential scan of 2,000 rows), sort, lock rows, limit | `stage_runs_claim_idx` |
| **Sweep**: leases that expired | Index Scan, lock rows, limit | `attempts_lease_expiry_idx` |
| **Sweep**: deadlines that passed | Index Scan, lock rows, limit | `attempts_deadline_idx` |
| **Sweep**: teardown deadlines that passed | Index Scan, lock rows, limit | `attempts_teardown_idx` |
| **Timeline**: outbox events of one job | Index Scan | `outbox_job_timeline_idx` |
| **Timeline**: ledger entries of one job | Bitmap Index Scan, bitmap heap scan, sort | `ledger_entries_pkey` |
| **Timeline**: stage runs of one job | Index Scan | `stage_runs_tenant_id_job_id_stage_kind_run_number_key` |
| **Timeline**: audit events of one job | Index Scan | `audit_events_job_idx` |
| **Ledger tail**: last entry of a job | Index Scan Backward, limit 1 | `ledger_entries_pkey` |
| **Audit tail**: last event of a tenant | Index Scan Backward, limit 1 | `audit_events_pkey` |
| **Relay**: unpublished outbox rows | Index Scan, lock rows, limit | `outbox_unpublished_idx` |
| **Authentication**: a token by hash | Index Scan, nested loop to `principals` | `api_tokens_token_hash_key` |
| **Invalidation**: runs that consumed one artifact hash | Index Scan | `stage_run_artifacts_hash_idx` |
| **Lookup**: one job by tenant and id | Index Scan | `jobs_tenant_id_id_execution_mode_key` |

### The claim plan in full

```text
Limit
  ->  LockRows
        ->  Sort
              Sort Key: s.not_before
              ->  Hash Join
                    Hash Cond: ((s.tenant_id = j.tenant_id) AND (s.job_id = j.id))
                    ->  Index Scan using stage_runs_claim_idx on stage_runs s
                          Index Cond: (not_before <= now())
                          Filter: (status = 'READY'::text)
                    ->  Hash
                          ->  Seq Scan on jobs j
                                Filter: (status = 'ACTIVE'::text)
```

The claim reaches `stage_runs` through the partial index, which holds only `READY` rows: 160 of 10,000. The planner joins to `jobs` with a hash join over a sequential scan, which is the right choice for 2,000 job rows. Once `jobs` is large the hash build becomes the expensive side, and a nested loop with key lookups wins. To check that this option exists, the suite forces it by switching hash and merge joins off:

```text
Limit
  ->  LockRows
        ->  Nested Loop
              ->  Index Scan using stage_runs_claim_idx on stage_runs s
                    Index Cond: (not_before <= now())
                    Filter: (status = 'READY'::text)
              ->  Memoize
                    Cache Key: s.tenant_id, s.job_id
                    Cache Mode: logical
                    ->  Index Scan using jobs_open_idx on jobs j
                          Index Cond: ((tenant_id = s.tenant_id) AND (id = s.job_id))
                          Filter: (status = 'ACTIVE'::text)
```

That forced plan is evidence that the index is usable for the join. It is not evidence of what the planner will choose at scale. Re-check with realistic row counts in `s1-database-review`.

### The sweep and the relay

```text
Limit
  ->  LockRows
        ->  Index Scan using attempts_lease_expiry_idx on attempts
              Index Cond: (lease_expires_at < now())
              Filter: (status = ANY ('{STARTING,RUNNING}'::text[]))

Limit
  ->  LockRows
        ->  Index Scan using outbox_unpublished_idx on outbox
              Filter: (published_at IS NULL)
```

The partial indexes cover only live attempts and only unpublished events. Their size follows the live work, not the history, which is the reason for them. They have no tenant column because the sweeper and the relay work across tenants under the system scope.

### The ledger tail

```text
Limit
  ->  Index Scan Backward using ledger_entries_pkey on ledger_entries
        Index Cond: ((tenant_id = '...'::uuid) AND (job_id = '...'::uuid))
```

The primary key `(tenant_id, job_id, sequence)` read backwards gives the head without a sort.

## What the plans show about forgetting the tenant

A lookup of a job by id alone, with no tenant, is still an index scan on PostgreSQL 18, which can skip-scan the composite key:

```text
Index Scan using jobs_tenant_id_id_execution_mode_key on jobs
  Index Cond: (id = '...'::uuid)
```

So a query that forgets `tenant_id` is not slow and nothing would flag it. See [tenancy.md](tenancy.md).

## Observations that are not failures

- The ledger timeline uses a bitmap scan and a sort rather than an ordered index scan, because it reads 100 of 10,000 rows. A job with thousands of entries reads them in index order.
- `principals` is read with a sequential scan in the authentication plan, because the table has five rows. It uses its key as the table grows.
- `jobs` carries two unique indexes that start with `(tenant_id, id)`, and the planner prefers the wider one for lookups. The narrower primary key is needed as the target of the foreign keys from other tables. The cost is one more index to maintain on each job write.
