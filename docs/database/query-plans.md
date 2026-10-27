# Query plans with row-level security on, at 10,000 and 100,000 rows

- Status: recorded from `scripts/db-test.sh plans` on 2026-10-27, PostgreSQL 18.6 (Homebrew), one laptop, `EXPLAIN (COSTS OFF)`. The 10,000 row run is the default. The 100,000 row run is `FACTORY_DB_PLANS_SCALE=10 scripts/db-test.sh plans` and took 191 seconds, almost all of it generating the data through the ledger and audit triggers. Both passed. The plans are text from one run each; the suite asserts only that the named index is used and that the large table is not scanned sequentially.
- Form: reference.
- Limits: this is the shape of the plans on a small, freshly analysed data set. It says nothing about timing, cache behaviour or bloat under load. The `s1-database-review` package measures those once there is a store to measure.
- What changed from the baseline: every plan is made **as the role that runs the query** with the policies on. The claim, the sweep and the relay run as `factory_system`. The timelines and lookups run as `factory_app` with the tenant setting. The two authentication lookups run as `factory_lookup`, the owner of the lookup functions (EXPLAIN cannot enter a function, so the body of each one is run as that role).

## The data

The suite builds the data inside the migrated schema as the owner, then runs `ANALYZE`. The right-hand column is the 100,000 row run.

| Table | Rows at scale 1 | Rows at scale 10 | Mix |
|---|---|---|---|
| `jobs` | 2,000 | 20,000 | 90% completed, 8% active, 1% paused, 1% failed. Five tenants. |
| `stage_runs` | 10,000 | 100,000 | 1.6% `READY` (160 and 1,600), 1.6% `RUNNING`, the rest `PASSED` or `PENDING`. |
| `attempts` | about 9,600 | about 96,000 | Mostly finished. About 1.6% live, of which about one in ten has an expired lease, and about 8 per 10,000 are `CANCELLING`. |
| `ledger_entries` | 10,000 | 100,000 | 100 (or 1,000) jobs with 100 valid hash-chained entries each, inserted through every trigger. |
| `outbox` | 10,000 | 100,000 | Five events per job. 99% published. |
| `audit_events` | 10,000 | 100,000 | Five tenants, valid chains. |
| `repositories` | 2,005 | 20,005 | Many repositories on five installations, as an organization-wide install has. New: the webhook binding needs them. |
| `api_tokens`, `artifacts`, `stage_run_artifacts` | 200, 2,000, 2,000 | the same | For the lookups by hash. |

Bulk status changes on `jobs`, `stage_runs`, `attempts` and `outbox` ran with triggers off, because they stand for months of earlier work. The ledger, audit and new outbox rows went through every trigger and constraint. That is why the suite can also check that the generated chains verify.

## The plans

| Query | Role | At 10,000 rows | At 100,000 rows |
|---|---|---|---|
| **Claim**: `READY` runs of `ACTIVE` jobs, `ORDER BY not_before LIMIT 10 FOR NO KEY UPDATE SKIP LOCKED` | system | Index Scan `stage_runs_claim_idx`, hash join to a sequential scan of `jobs` (2,000 rows) | Index Scan `stage_runs_claim_idx`, **nested loop with a memoized Index Scan `jobs_open_idx`** |
| **Sweep**: leases that expired, `FOR NO KEY UPDATE SKIP LOCKED` | system | Index Scan `attempts_lease_expiry_idx` | the same |
| **Sweep**: deadlines that passed | system | Index Scan `attempts_deadline_idx` | the same |
| **Sweep**: teardown deadlines that passed | system | Index Scan `attempts_teardown_idx` | the same |
| **Relay**: unpublished outbox rows, `FOR UPDATE SKIP LOCKED` | system | Index Scan `outbox_unpublished_idx` | the same |
| **Timeline**: outbox events of one job | tenant | Index Scan `outbox_job_timeline_idx` | the same |
| **Timeline**: ledger entries of one job | tenant | Bitmap Index Scan `ledger_entries_pkey`, sort | Index Scan `ledger_entries_tenant_id_job_id_sequence_entry_hash_key` (no sort) |
| **Timeline**: stage runs of one job | tenant | Index Scan `stage_runs_tenant_id_job_id_stage_kind_run_number_key` | the same |
| **Timeline**: audit events of one job | tenant | Index Scan `audit_events_job_idx` | the same |
| **Ledger tail**: last entry of a job | tenant | Index Scan Backward `ledger_entries_pkey`, limit 1 | Index Only Scan Backward `ledger_entries_tenant_id_job_id_sequence_entry_hash_key` |
| **Audit tail**: last event of a tenant | tenant | Index Scan Backward `audit_events_pkey`, limit 1 | the same |
| **Authentication**: a token by hash, the body of `resolve_token` | lookup | Index Scan `api_tokens_token_hash_key`; `principals` and `tenants` by sequential scan (5 rows each) | the same |
| **Authentication** through the view | tenant | the same shape, with the policy as a filter on each table | the same |
| **Webhook binding**: a repository by installation and GitHub repository id, the body of `resolve_installation` | lookup | Index Scan `repositories_github_repository_id_key`, filter on the installation | the same |
| **Invalidation**: runs that consumed one artifact hash | tenant | Index Scan `stage_run_artifacts_hash_idx` | the same |
| **Lookup**: one job by tenant and id | tenant | Index Scan `jobs_tenant_id_id_execution_mode_key` | the same |

All sixteen use an index on the large table at both sizes. The claim and sweep plans, the done criterion, are unchanged in shape by the policy: the system role's policies are `USING (true)`, which PostgreSQL drops from the plan, so there is no filter to add.

### The claim plan in full

At 10,000 rows (2,000 jobs):

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

At 100,000 rows (20,000 jobs) the planner moves to the key lookup that the baseline could only show by switching hash joins off:

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

The partial index holds only `READY` rows: 160 of 10,000, 1,600 of 100,000. The suite still forces the nested loop at 10,000 rows (hash and merge joins off) as a check that the option exists.

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

The partial indexes cover only live attempts and only unpublished events. Their size follows the live work, not the history. They have no tenant column because the sweeper and the relay work across tenants under the system scope. The sweep now locks with `FOR NO KEY UPDATE`, as the claim does: a ledger entry points at an attempt, and `FOR UPDATE` would block it.

### What the policy adds to a tenant query

A query that already names the tenant gets a **One-Time Filter** that compares the setting with the tenant in the query, and then runs as before:

```text
Result
  One-Time Filter: ((NULLIF(current_setting('factory.tenant_id'::text, true), ''::text))::uuid = '00000000-0000-7000-8000-000000000003'::uuid)
  ->  Index Scan using outbox_job_timeline_idx on outbox
        Index Cond: ((tenant_id = '00000000-0000-7000-8000-000000000003'::uuid) AND (job_id = '...'::uuid))
```

The filter is evaluated once, before the scan. If the query names a tenant other than the session's, the scan never runs. A query that does **not** name the tenant gets the policy as an index condition instead, so it is still an index scan:

```text
Index Scan using jobs_tenant_id_id_execution_mode_key on jobs
  Index Cond: ((tenant_id = (NULLIF(current_setting('factory.tenant_id'::text, true), ''::text))::uuid) AND (id = '...'::uuid))
```

This is the case of the missing `WHERE tenant_id = $1`. Without row-level security it was an index scan too (PostgreSQL 18 skip-scans the composite key), fast and silently reading another tenant's rows. With it, the same query is as fast and returns only the session's tenant: the suite shows tenant 3 finding its job by id alone and tenant 1 getting zero rows.

One timeline query was also run with `EXPLAIN ANALYZE` as the owner and as the tenant role: 0.040 ms and 0.023 ms at 10,000 rows, 0.055 ms and 0.015 ms at 100,000. These are single warm-or-cold runs and the order differs between them. They show no cost large enough to see; they do not measure the cost of the policy, and nothing here claims to. The extra statement per transaction (`set_config`) is one round trip, measured in `s1-database-review`.

## Observations that are not failures

- The ledger timeline uses a bitmap scan and a sort at 10,000 rows, because it reads 100 of 10,000. At 100,000 rows the planner takes the other index that starts with `(tenant_id, job_id, sequence)`, `ledger_entries_tenant_id_job_id_sequence_entry_hash_key`, in order and with no sort. The ledger therefore has two indexes with the same first three columns: the primary key and the unique key that the job's head pointer references. Either serves the timeline and the tail, and the suite accepts either. Whether to keep both is a question for `s1-database-review`.
- `principals` and `tenants` are read with sequential scans in the authentication plans, because each has five rows. They use their keys as the tables grow. `tenants` is read to check that the tenant is not disabled.
- `jobs` carries two unique indexes that start with `(tenant_id, id)`, and the planner prefers the wider one for lookups. The narrower primary key is needed as the target of the foreign keys from other tables. The cost is one more index to maintain on each job write.
- The `repositories` table has to be large for the webhook binding to show an index scan. With five rows the planner joins two sequential scans, which is the right plan for five rows.
