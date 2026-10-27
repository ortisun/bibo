# Notes for the storage crate

- Status: written for the engineer who builds `s1-storage-postgres`. Every statement below is backed by a test in [`tests/`](tests/) or by the generated [`schema.rs`](../../crates/storage/src/schema.rs). Where something is a recommendation and was not run in Rust, it says so.
- Form: how-to guide and reference.
- The reference SQL for the claim, the renewal, the webhook receiver and the consumer is in `tests/lease.sql`, `tests/webhook_delivery.sql` and `tests/outbox.sql`. Copy from there: those statements are the ones the tests ran.

## Prerequisites

- The migrations applied (see [running.md](running.md)).
- A login role that is a member of `factory_app`. The application connects as that login, never as the table owner.
- The owner role for fixtures that create tenants. The application role cannot insert into `tenants`, by design (onboarding is an owner action).

## Connecting

1. Create a login role per service and make it a member: `CREATE ROLE factory_api LOGIN IN ROLE factory_app;` with a password from the secret store. The migrations create `factory_app` as `NOLOGIN` and do not set any password.
2. Run migrations as the table owner from a deploy step. Never from the application (ADR 0007, rule 1).
3. At start-up `Store::schema_version` can run `SELECT max(version) FROM __diesel_schema_migrations`. The last migration grants the application role `SELECT` on that table, and nothing else on it. Refuse to become ready when the number is behind the one the code was built for.

## Diesel facts that differ from the usual

- **Composite primary keys.** Every tenant-owned table has `(tenant_id, id)` as its key, so `table.find((tenant, id))` is the only way to find by key. This is intended: a lookup by id alone does not compile.
- **No `joinable!` for composite foreign keys.** `diesel print-schema` writes `joinable!` only for single-column keys, so only the keys to `tenants` appear. Write joins with `.on(...)` and include the tenant in the condition.
- **Views are not in `schema.rs`.** `active_api_tokens`, `ledger_current_claims` and `ledger_assurance_levels` need a hand-written `table!` in `crates/storage/src/pg/`, or `sql_query`. Do not add them to `schema.rs`: the migrations test regenerates that file and compares it.
- **Columns the database assigns.** Leave these out of the `Insertable` struct and the database fills them: `audit_events.sequence`, `created_at`, `prev_sequence`, `prev_hash`, `canonical_json`, `hash`; `ledger_entries.prev_sequence` and `inserted_at`; `outbox.seq` (`GENERATED ALWAYS`, a supplied value is an error). They are `NOT NULL`, and the `BEFORE INSERT` trigger runs before the null check.
- **Generated order.** Diesel's `table!` for `outbox` lists `seq` first. It is an identity column and the application role needs no sequence privilege for it.

## Errors

Diesel reports SQLSTATE 23505, 23503 and 23514 as `UniqueViolation`, `ForeignKeyViolation` and `CheckViolation`, and gives the constraint name through `DatabaseErrorInformation::constraint_name()`. The triggers in these migrations set the constraint name on purpose, so the adapter can map precisely. Everything else arrives as `Unknown` with the message.

| SQLSTATE and constraint | What happened | Suggested `StoreError` |
|---|---|---|
| 0 rows updated by a `WHERE id = $1 AND version = $2` | Someone else changed the row | `Conflict` |
| 23505 `outbox_one_event_per_aggregate_version` | The event for this version already exists | `Conflict` (an idempotent replay) |
| 23505 `attempts_one_active_per_stage_run` | Another attempt is live | `Conflict` |
| 23505 `ledger_entries_pkey` | Someone appended at this position first | `ChainBroken` or retry |
| 23505 `jobs_tenant_id_webhook_delivery_id_key`, `jobs_tenant_id_idempotency_key_key` | The job already exists | return the first job |
| 23505 `webhook_deliveries_*_key` | A repeated delivery | not an error: use `ON CONFLICT DO NOTHING` |
| 23503, any composite key | A reference to another tenant's or another job's row, or to nothing | `TenantMismatch` or `Constraint` |
| 23503 on the key to the previous ledger entry (`ledger_entries_tenant_id_job_id_prev_sequence_prev_entry_h_fkey`) | The predecessor does not exist | `ChainBroken` |
| 23514 `<table>_legal_transition`, `<table>_initial_state` | The engine tried a move the state machine does not allow (a domain bug) | `Constraint` |
| 23514 `<table>_version_bump` | An update forgot `version = version + 1` (a storage bug) | `Constraint` |
| 23514 `stage_runs_terminal_is_immutable`, `attempts_terminal_is_immutable`, `attempts_live_attempt_has_current_epoch` | A write to a finished run or attempt, or with a stale epoch | `LeaseFenced` for attempts, `Conflict` for runs |
| 23514 `ledger_entries_hash_matches_document`, `ledger_entries_document_matches_columns` | The entry does not match its hash or its document | `ChainBroken` |
| 23514 `outbox_aggregate_exists`, `outbox_aggregate_belongs_to_job`, `outbox_aggregate_has_reached_version` | The event is inconsistent with its aggregate | `Constraint` |
| 42501 with "is append-only" | An update or delete of the ledger or audit log | `Constraint` (a bug) |
| 42501 "permission denied" | A missing grant | a bug; fail loudly |

The constraint checks on `outbox_aggregate_*` and on `attempts_live_attempt_has_current_epoch` are deferred, so they fire at `COMMIT`, not at the statement. Map errors from `commit()` as well.

## Recipes

Each recipe names the test that ran it.

### Locking

Use `FOR NO KEY UPDATE`, never `FOR UPDATE`, when you lock a job, a stage run or an attempt. A ledger, audit or outbox insert takes a `KEY SHARE` lock on the rows it points at, and `FOR UPDATE` conflicts with that. The `lease` suite holds one stage run `FOR NO KEY UPDATE` and another `FOR UPDATE` for two seconds, then appends a ledger entry for each with a 500 ms lock timeout. The first append goes through. The second fails with a lock timeout. ADR 0007 says `FOR UPDATE SKIP LOCKED`. `FOR NO KEY UPDATE SKIP LOCKED` gives the same exclusion between claimers and does not block the writers of evidence. Diesel has `for_no_key_update()`.

### Claim a stage run (`tests/lease.sql`, function `dbtest.claim`)

```sql
SELECT s.tenant_id, s.id, s.job_id, s.version
  FROM stage_runs s
  JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE'
 WHERE s.status = 'READY' AND s.not_before <= now()
 ORDER BY s.not_before LIMIT 1
 FOR NO KEY UPDATE OF s SKIP LOCKED;

UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, version = version + 1
 WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = 'READY';   -- zero rows: lost the race

INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch,
                      lease_expires_at, deadline_at)
SELECT s.tenant_id, $4, s.job_id, s.id, (SELECT coalesce(max(attempt_number), 0) + 1 FROM attempts
       WHERE tenant_id = s.tenant_id AND stage_run_id = s.id), $5, s.lease_epoch,
       now() + interval '30 seconds', now() + $6
  FROM stage_runs s WHERE s.tenant_id = $1 AND s.id = $2;
```

Run all three in one transaction. The `claimed` race (25 rounds, 4 workers) ends with one winner every time, and so do a bare compare-and-swap and a bare insert of a live attempt. Write the lease expiry as `now() + interval`, never a timestamp computed on the worker: the database refuses an expiry more than an hour ahead, but a few minutes of skew would pass.

### Renew a lease (`dbtest.renew`)

```sql
UPDATE attempts SET lease_expires_at = now() + interval '30 seconds', last_heartbeat_at = now(), version = version + 1
 WHERE tenant_id = $1 AND id = $2 AND lease_owner = $3 AND lease_epoch = $4
   AND status IN ('STARTING', 'RUNNING') AND lease_expires_at > now();
```

Zero rows means the caller no longer holds the lease. A wrong owner, tenant or epoch, an attempt that is not live, and a lease that expired by the database clock all give zero rows (tested one by one). A heartbeat raises `version`, so a stale transition by the sweeper fails its compare and swap and retries.

### Sweep expired leases and deadlines

```sql
UPDATE attempts SET status = 'LEASE_LOST', ended_at = now(), version = version + 1
 WHERE status IN ('STARTING', 'RUNNING') AND lease_expires_at < now()
RETURNING tenant_id, id, stage_run_id;
```

The `lease` suite runs this as the application role. The sweep takes only the expired attempt and leaves a live lease alone. The partial indexes behind it are in [query-plans.md](query-plans.md). A retry then sets the stage run back to `READY` with `not_before = now() + back_off`, and the claim honours it.

### One decision, one transaction (`tests/outbox.sql`, section 5)

```text
BEGIN;
  UPDATE jobs SET status = ..., ledger_head_sequence = ..., ledger_head_hash = ..., version = version + 1
   WHERE tenant_id = $1 AND id = $2 AND version = $3;   -- one compare and swap; 0 rows: Conflict
  INSERT INTO ledger_entries (...) ...;                 -- hash computed by the domain code
  INSERT INTO outbox (...) ...;                         -- names the transition, announces the new version
  INSERT INTO audit_events (...) ...;                   -- last: it holds a per-tenant lock until commit
COMMIT;
```

The ledger entry and the event may come before the job update, because the checks that span rows are deferred. If any statement fails, nothing remains: the suite injects a fault before and after the event insert and checks the job, the ledger and the outbox each time.

An outbox event announces `aggregate.version` after the change. Move the status and the ledger head in one `UPDATE`, so the version rises by one and that is the number to announce. The database refuses an event whose aggregate has not reached the announced version (`outbox_aggregate_has_reached_version`). It does not refuse one that announces an older version than the row now has.

### Append a ledger entry

1. Build the entry and its RFC 8785 canonical JSON without `entry_hash`. Compute `entry_hash` as `sha256:` plus the hex of SHA-256 over `prev_entry_hash`, a newline and the canonical text. Use the vectors in [ledger-and-audit.md](ledger-and-audit.md) as your first test.
2. Insert with `canonical_json` set to that exact text, the queryable columns filled from the same values, and `prev_entry_hash` set. Leave `prev_sequence` out.
3. Lock the job row `FOR NO KEY UPDATE` first if you want writers to queue, or retry on `ledger_entries_pkey`.

### Receive a webhook (`tests/webhook_delivery.sql`, function `dbtest.receive_delivery`)

```sql
INSERT INTO webhook_deliveries (...) VALUES (...) ON CONFLICT DO NOTHING RETURNING id;
-- no row returned: a repeat. Acknowledge and stop. Otherwise, in the same transaction:
INSERT INTO jobs (..., webhook_delivery_id) VALUES (..., $delivery_row_id);
```

Fifty concurrent copies of one delivery give one new row and no error in any of them. The body hash and semantic key conflicts are absorbed by the same `ON CONFLICT DO NOTHING`.

### Consume an event (`tests/outbox.sql`, function `dbtest.consume`)

```sql
INSERT INTO inbox (tenant_id, consumer, event_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING RETURNING event_id;
-- no row returned: already handled. Otherwise apply the effect in the same transaction.
```

### Relay the outbox

```sql
SELECT seq, event_id FROM outbox WHERE published_at IS NULL ORDER BY seq LIMIT 100 FOR UPDATE SKIP LOCKED;
UPDATE outbox SET published_at = now(), publish_attempts = publish_attempts + 1 WHERE tenant_id = $1 AND event_id = $2;
```

The relay needs the `UPDATE` grant on `published_at` to run `FOR UPDATE`, which it has. `seq` has gaps after rollbacks and can commit out of order, so consumers must order by `aggregate.version`. A later migration may give the relay its own role.

### Authenticate a token

```sql
SELECT tenant_id, principal_id FROM active_api_tokens WHERE token_hash = $1 AND audience = $2;
```

Hash the presented token with SHA-256 in the API and pass the 32 bytes. Zero rows covers unknown, expired, revoked, wrong audience and disabled owner alike, so the API cannot tell the caller which it was.

### Check that an approval still counts (`tests/approvals.sql`)

```sql
SELECT count(*) FROM approvals
 WHERE tenant_id = $1 AND job_id = $2 AND decision = 'approve' AND pr_head_sha = $current_head
   AND invalidated_at IS NULL AND expires_at > now();
```

## What the tests assume of the storage crate

- The domain's hash function reproduces the two published vectors.
- Every method takes a tenant scope and puts the tenant in every `WHERE` and every join. The database cannot notice a forgotten tenant (see [tenancy.md](tenancy.md)).
- Fixtures that create tenants, repositories' parents or principals' parents run as the owner.
- The storage tests that need to tamper with a ledger row (the byte-flip test in `s1-storage-postgres`) must do it as the owner with `ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_no_change`, or with `SET session_replication_role = replica` as a superuser.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `must be owner of table` when running a migration | The migration ran as `factory_app` or another member. Run as the owner. |
| `ledger_entries_hash_matches_document` on the first insert | The hash formula differs: prefix on the previous hash, a newline, or the canonical text that was hashed is not the text that was stored. |
| `ledger_entries_document_matches_columns` | A column was filled from a different value than the JSON, or the timestamp has a different instant. |
| Inserts into `audit_events` queue up | Transactions write audit events early and then continue for a long time. Write them last. |
| A claim returns nothing although a stage run is `READY` | `not_before` is in the future, the job is not `ACTIVE`, or another claimer holds the row. |
| `attempts_live_attempt_has_current_epoch` at commit | The attempt was created at an old epoch, or the stage run was not moved to `RUNNING` with `lease_epoch + 1` in the same transaction. |
