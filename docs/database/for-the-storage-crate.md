# Notes for the storage crate

- Status: written for the engineer who builds `s1-storage-postgres`, after the work package `s1-database-tenancy-and-state-sync` turned on row-level security (ADR 0012). Every statement below is backed by a test in [`tests/`](tests/) or by the generated [`schema.rs`](../../crates/storage/src/schema.rs). Where something is a recommendation and was not run in Rust, it says so. No Rust code was run against this database.
- Form: how-to guide and reference.
- The reference SQL for the claim, the sweep, the renewal, the webhook receiver and the consumer is in `tests/lease.sql`, `tests/webhook_delivery.sql` and `tests/outbox.sql`. Copy from there: those statements are the ones the tests ran, as the roles that the storage crate will use.
- Why the rules are what they are: [tenancy.md](tenancy.md).

## Prerequisites

- The migrations applied (see [running.md](running.md)).
- **Three logins**, created by the deployment, never by the application. The migrations create the four groups as `NOLOGIN` roles and set no password:

  ```sql
  CREATE ROLE factory_api    LOGIN PASSWORD '...' IN ROLE factory_app, factory_resolver;  -- the API process
  CREATE ROLE factory_worker LOGIN PASSWORD '...' IN ROLE factory_app;                    -- tenant pool of the workflow and worker
  CREATE ROLE factory_engine LOGIN PASSWORD '...' IN ROLE factory_system;                 -- system pool of the workflow only
  ```

  Do not use `NOINHERIT`: a policy and a grant reach a login through its membership, and a `NOINHERIT` login would need `SET ROLE` first. **No login may be a member of both `factory_app` and `factory_system`**: permissive policies are combined with OR, and such a login reads every tenant's rows. The workflow process that needs both holds two logins and two pools.
- The owner role for fixtures that create tenants. The application role cannot insert into `tenants`, by design (onboarding is an owner action). Under `FORCE ROW LEVEL SECURITY` the owner sees no tenant row and can write none, so a fixture that needs rows in tenant tables writes them as `factory_app` with the setting made, or as a superuser. See [tenancy.md](tenancy.md).

## What the storage crate must do, in order

1. **Two pools, two logins.** `Store::begin` uses the tenant login. `Store::begin_system` uses the system login. `resolve_token` and `resolve_installation` use the API login (which is also a tenant login: they run outside a `Tx`, as plain function calls, with no setting).
2. **At start-up, for each pool,** run the query in [`tests/role_readiness.sql`](tests/role_readiness.sql) as that pool's login, and refuse to become ready unless the answer is right: not a superuser, no `BYPASSRLS`, owns no relation, in the right group and not in the other. The `rls` suite runs it as three real logins and as a superuser.

   | Pool | `superuser, bypassrls, owns_relations, tenant_group, system_group, resolver_group, lookup_group` |
   |---|---|
   | Tenant | `f, f, f, t, f, f, f` |
   | API | `f, f, f, t, f, t, f` |
   | System | `f, f, f, f, t, f, f` |

   Also read `max(version)` from `__diesel_schema_migrations` (both pools may) and refuse when it is behind the code.
3. **Every tenant statement runs inside a `Tx`, and a `Tx` starts like this**, as its first statement:

   ```sql
   SELECT set_config('factory.tenant_id', $1, true);   -- $1: the tenant's uuid in its text form, bound as a parameter
   ```

   The third argument `true` makes it local to the transaction. In Diesel: `diesel::sql_query("SELECT set_config('factory.tenant_id', $1, true)").bind::<Text, _>(tenant.to_string()).execute(&mut conn)` inside `AsyncConnection::transaction`. The extended protocol with a bound parameter was tried with `psql \bind`; `diesel-async` itself was not run.
4. **The `Tx` has no method that runs raw SQL or changes the setting.** No `Store` method runs a statement outside a `Tx` (apart from the two lookups).
5. **A repository method still puts `tenant_id` in its `WHERE` clauses and joins.** The policy hides other tenants' rows. The keys and the `WHERE` catch a wrong tenant on a write, and keep an unscoped query from reading by accident what the policy would let through if the setting were wrong.
6. **When a connection goes back to the pool,** run `RESET factory.tenant_id` (cheap, keeps prepared statements). `DISCARD ALL` also works and drops the statement cache. The local setting already ends at commit, so this guards against a session-level `SET`, which nothing in `Store` makes and which would otherwise show its tenant to the next borrower.

### What not to do

| Do not | Why | Shown by |
|---|---|---|
| `SET factory.tenant_id = ...` or `set_config(..., false)` | Session level. It survives the transaction on a pooled connection and is the next borrower's tenant | `rls` shell, "KNOWN LIMIT: a session-level SET" |
| Run a statement outside a transaction that began with the setting | With no setting the session sees zero rows and gets no error, which looks like "not found" | `rls` shell, first checks |
| Use a connection from the tenant pool for the claim, the sweep or the relay | It sees one tenant. Use the system pool | `rls` section 4 |
| Give one login both groups, or connect as the owner or a superuser | The policies are bypassed or combined | `rls` section 1, readiness query |
| Pass the tenant as a SQL literal | `pg_stat_activity` and the logs would carry it, and a literal is the first step of an injection. Bind it | recommendation |
| `COPY ... FROM` into a tenant table | PostgreSQL refuses it under row-level security. Use `INSERT` (several rows per statement) | `rls` shell |
| `INSERT ... ON CONFLICT DO UPDATE` on the two global keys (`repositories.github_repository_id`, `api_tokens.token_hash`) | The existing row may belong to another tenant and be invisible to the session; the update then fails the policy, and `DO NOTHING` silently skips. Insert and map the unique violation | `tenancy` section 4 |
| Run `audit_verify_chain` or `ledger_verify_chain` from a session set to another tenant | They read under the caller's policy, find nothing and answer NULL, which looks like "sound" | `rls` section 7 |
| Send the database's message to a client | A unique violation names the key; for the global keys it tells a tenant that another one holds the value | `tenancy` section 4 |
| Read `SELECT *` from `stage_runs`, `jobs` or `attempts` on the system pool | The system role may read named columns only. Select the columns the loop needs | `rls` section 4 |

## Connecting

1. Run migrations as the table owner from a deploy step. Never from the application (ADR 0007, rule 1). The migration role must be a superuser, or the role that created the groups (`factory_lookup` is handed to itself for a moment so that it can own the lookup functions). Otherwise migration 14 stops with a message that says so.
2. Create the logins above with passwords from the secret store.
3. At start-up each pool runs the readiness query and the schema version check.

## Diesel facts that differ from the usual

- **Composite primary keys.** Every tenant-owned table has `(tenant_id, id)` as its key, so `table.find((tenant, id))` is the only way to find by key. This is intended: a lookup by id alone does not compile.
- **No `joinable!` for composite foreign keys.** `diesel print-schema` writes `joinable!` only for single-column keys, so only the keys to `tenants` appear. Write joins with `.on(...)` and include the tenant in the condition.
- **Views are not in `schema.rs`.** `active_api_tokens`, `ledger_current_claims` and `ledger_assurance_levels` need a hand-written `table!` in `crates/storage/src/pg/`, or `sql_query`. Do not add them to `schema.rs`: the migrations test regenerates that file and compares it.
- **Functions are not in `schema.rs` either.** Declare `resolve_token` and `resolve_installation` with `diesel::define_sql_function!` or call them with `sql_query`.
- **Columns the database assigns.** Leave these out of the `Insertable` struct and the database fills them: `audit_events.sequence`, `created_at`, `prev_sequence`, `prev_hash`, `canonical_json`, `hash`; `ledger_entries.prev_sequence` and `inserted_at`; `outbox.seq` (`GENERATED ALWAYS`, a supplied value is an error). They are `NOT NULL`, and the `BEFORE INSERT` trigger runs before the null check.
- **Generated order.** Diesel's `table!` for `outbox` lists `seq` first. It is an identity column and the application role needs no sequence privilege for it.
- **Prepared statements are safe across tenants.** A generic plan made for one tenant gives the next tenant its own rows, because the policy reads the setting when the statement runs. Tried with `plan_cache_mode = force_generic_plan`.

## Errors

Diesel reports SQLSTATE 23505, 23503 and 23514 as `UniqueViolation`, `ForeignKeyViolation` and `CheckViolation`, and gives the constraint name through `DatabaseErrorInformation::constraint_name()`. The triggers in these migrations set the constraint name on purpose, so the adapter can map precisely. Everything else arrives as `Unknown` with the message.

| SQLSTATE and constraint | What happened | Suggested `StoreError` |
|---|---|---|
| 0 rows updated by a `WHERE id = $1 AND version = $2` | Someone else changed the row | `Conflict` |
| 0 rows from a read or an update of a row that exists | The row belongs to another tenant, or the setting was not made. Indistinguishable by design (NT-TEN-05) | `NotFound` |
| 42501 "new row violates row-level security policy for table" | A write for a tenant other than the transaction's, or with no setting. A storage bug | fail loudly; never show it |
| 22P02 `invalid input syntax for type uuid` on a tenant table | The setting is not a uuid. A storage bug | fail loudly |
| 23505 `outbox_one_event_per_aggregate_version` | The event for this version already exists | `Conflict` (an idempotent replay) |
| 23505 `attempts_one_active_per_stage_run` | Another attempt is live | `Conflict` |
| 23505 `ledger_entries_pkey` | Someone appended at this position first | `ChainBroken` or retry |
| 23505 `jobs_tenant_id_webhook_delivery_id_key`, `jobs_tenant_id_idempotency_key_key` | The job already exists | return the first job |
| 23505 `webhook_deliveries_*_key` | A repeated delivery | not an error: use `ON CONFLICT DO NOTHING` |
| 23505 `repositories_github_repository_id_key`, `api_tokens_token_hash_key` | Another tenant (or this one) holds the value | the same closed error as a missing object; never the message |
| 23503, any composite key | A reference to another tenant's or another job's row, or to nothing | `TenantMismatch` or `Constraint` |
| 23503 on the key to the previous ledger entry (`ledger_entries_tenant_id_job_id_prev_sequence_prev_entry_h_fkey`) | The predecessor does not exist | `ChainBroken` |
| 23514 `<table>_legal_transition`, `<table>_initial_state` | The engine tried a move the state machine does not allow (a domain bug) | `Constraint` |
| 23514 `<table>_version_bump` | An update forgot `version = version + 1` (a storage bug) | `Constraint` |
| 23514 `stage_runs_terminal_is_immutable`, `attempts_terminal_is_immutable`, `attempts_live_attempt_has_current_epoch` | A write to a finished run or attempt, or with a stale epoch | `LeaseFenced` for attempts, `Conflict` for runs |
| 23514 `ledger_entries_hash_matches_document`, `ledger_entries_document_matches_columns` | The entry does not match its hash or its document | `ChainBroken` |
| 23514 `outbox_aggregate_exists`, `outbox_aggregate_belongs_to_job`, `outbox_aggregate_has_reached_version` | The event is inconsistent with its aggregate | `Constraint` |
| 42501 with "is append-only" | An update or delete of the ledger or audit log | `Constraint` (a bug) |
| 42501 "permission denied" | A missing grant, or a statement the role may not make (a whole-row read on the system pool, a function the login may not run) | a bug; fail loudly |

The constraint checks on `outbox_aggregate_*` and on `attempts_live_attempt_has_current_epoch` are deferred, so they fire at `COMMIT`, not at the statement. Map errors from `commit()` as well.

Never pass the database's message or detail text to an API client. A unique violation names the key value in its detail, and the two keys that are global could tell a caller that another tenant already holds that repository or token. Log it, and return the closed error. NT-TEN-05 asks for the same answer for a missing object and a foreign one.

## Recipes

Each recipe names the test that ran it. "Tenant transaction" means a transaction that began with the `set_config` statement above, on the tenant pool.

### Locking

Use `FOR NO KEY UPDATE`, never `FOR UPDATE`, when you lock a job, a stage run or an attempt. A ledger, audit or outbox insert takes a `KEY SHARE` lock on the rows it points at, and `FOR UPDATE` conflicts with that. The `lease` suite holds one stage run `FOR NO KEY UPDATE` and another `FOR UPDATE`, both as the system role, for two seconds, then appends a ledger entry for each as the tenant role with a 500 ms lock timeout. The first append goes through. The second fails with a lock timeout. ADR 0007 as revised says `FOR NO KEY UPDATE SKIP LOCKED`. Diesel has `for_no_key_update()`. The relay locks the outbox `FOR UPDATE`, which nothing points at.

### Claim a stage run (`tests/lease.sql`, function `dbtest.claim`)

Two transactions, two pools. **Step 1, system transaction:** find a candidate and return identifiers.

```sql
SELECT s.tenant_id, s.id, s.job_id, s.version
  FROM stage_runs s
  JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE'
 WHERE s.status = 'READY' AND s.not_before <= now()
 ORDER BY s.not_before LIMIT 1
 FOR NO KEY UPDATE OF s SKIP LOCKED;
```

Commit it. The system role cannot read other columns, so name them. **Step 2, tenant transaction for `s.tenant_id`:**

```sql
UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, version = version + 1
 WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = 'READY';   -- zero rows: lost the race

INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch,
                      lease_expires_at, deadline_at)
SELECT s.tenant_id, $4, s.job_id, s.id, (SELECT coalesce(max(attempt_number), 0) + 1 FROM attempts
       WHERE tenant_id = s.tenant_id AND stage_run_id = s.id), $5, s.lease_epoch,
       now() + interval '30 seconds', now() + $6
  FROM stage_runs s WHERE s.tenant_id = $1 AND s.id = $2;
```

The two steps cannot share one transaction (the roles differ and the lock would deadlock the second connection), so **two workers can find the same run**. The compare and swap on `version` and the unique index of one live attempt decide. The `rls` suite runs 12 rounds of four workers through two real logins: in 7 or 8 of the 12 rounds more than one worker had the same candidate, and every round ended with exactly one winner. The `lease` suite also races the swap alone and a bare insert of a live attempt, 25 rounds each, as the tenant role. Write the lease expiry as `now() + interval`, never a timestamp computed on the worker: the database refuses an expiry more than an hour ahead, but a few minutes of skew would pass.

### Renew a lease (`dbtest.renew`), in a tenant transaction

```sql
UPDATE attempts SET lease_expires_at = now() + interval '30 seconds', last_heartbeat_at = now(), version = version + 1
 WHERE tenant_id = $1 AND id = $2 AND lease_owner = $3 AND lease_epoch = $4
   AND status IN ('STARTING', 'RUNNING') AND lease_expires_at > now();
```

Zero rows means the caller no longer holds the lease. A wrong owner, tenant or epoch, an attempt that is not live, and a lease that expired by the database clock all give zero rows (tested one by one). A heartbeat raises `version`, so a stale transition by the sweeper fails its compare and swap and retries.

### Sweep expired leases and deadlines (`dbtest.sweep`)

Step 1, system transaction:

```sql
SELECT tenant_id, id, version FROM attempts
 WHERE status IN ('STARTING', 'RUNNING') AND lease_expires_at < now()
 ORDER BY lease_expires_at LIMIT 100 FOR NO KEY UPDATE SKIP LOCKED;
```

Step 2, a tenant transaction per tenant found, for each attempt:

```sql
UPDATE attempts SET status = 'LEASE_LOST', ended_at = now(), version = version + 1
 WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status IN ('STARTING', 'RUNNING') AND lease_expires_at < now();
```

The `lease` suite runs both steps. The sweep takes only the expired attempt and leaves a live lease alone. A retry then sets the stage run back to `READY` with `not_before = now() + back_off` in the same tenant transaction as its ledger entry and event, and the claim honours it. The partial indexes behind the finding queries are in [query-plans.md](query-plans.md).

### One decision, one transaction (`tests/outbox.sql`, section 5), a tenant transaction

```text
BEGIN;
  SELECT set_config('factory.tenant_id', $tenant, true);   -- first
  UPDATE jobs SET status = ..., ledger_head_sequence = ..., ledger_head_hash = ..., version = version + 1
   WHERE tenant_id = $1 AND id = $2 AND version = $3;   -- one compare and swap; 0 rows: Conflict
  INSERT INTO ledger_entries (...) ...;                 -- hash computed by the domain code
  INSERT INTO outbox (...) ...;                         -- names the transition, announces the new version
  INSERT INTO audit_events (...) ...;                   -- last: it holds a per-tenant lock until commit
COMMIT;
```

The ledger entry and the event may come before the job update, because the checks that span rows are deferred. If any statement fails, nothing remains: the suite injects a fault before and after the event insert and checks the job, the ledger and the outbox each time.

An outbox event announces `aggregate.version` after the change. Move the status and the ledger head in one `UPDATE`, so the version rises by one and that is the number to announce. The database refuses an event whose aggregate has not reached the announced version (`outbox_aggregate_has_reached_version`). It does not refuse one that announces an older version than the row now has.

### Append a ledger entry, in a tenant transaction

1. Build the entry and its RFC 8785 canonical JSON without `entry_hash`. Compute `entry_hash` as `sha256:` plus the hex of SHA-256 over `prev_entry_hash`, a newline and the canonical text. Use the vectors in [ledger-and-audit.md](ledger-and-audit.md) as your first test.
2. Insert with `canonical_json` set to that exact text, the queryable columns filled from the same values, and `prev_entry_hash` set. Leave `prev_sequence` out.
3. Lock the job row `FOR NO KEY UPDATE` first if you want writers to queue, or retry on `ledger_entries_pkey`.

### Receive a webhook (`tests/webhook_delivery.sql`, function `dbtest.receive_delivery`)

1. **Before any tenant is known,** verify the signature, then call `resolve_installation(installation_id, github_repository_id)` on the API pool, outside a `Tx`. Zero rows: the installation or repository is unknown, disabled, or the pair does not belong together, and the caller is not told which. Record a `webhook.rejected` audit event in a tenant transaction **for the platform tenant** `00000000-0000-0000-0000-000000000001` (see [tenancy.md](tenancy.md): the ports need a platform scope for this) and answer as for any bad request.
2. **With the tenant,** open a tenant transaction and:

```sql
INSERT INTO webhook_deliveries (...) VALUES (...) ON CONFLICT DO NOTHING RETURNING id;
-- no row returned: a repeat. Acknowledge and stop. Otherwise, in the same transaction:
INSERT INTO jobs (..., webhook_delivery_id) VALUES (..., $delivery_row_id);
```

Fifty concurrent copies of one delivery give one new row and no error in any of them, as the tenant role. The body hash and semantic key conflicts are absorbed by the same `ON CONFLICT DO NOTHING`.

### Consume an event (`tests/outbox.sql`, function `dbtest.consume`), in a tenant transaction

```sql
INSERT INTO inbox (tenant_id, consumer, event_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING RETURNING event_id;
-- no row returned: already handled. Otherwise apply the effect in the same transaction.
```

### Relay the outbox, on the system pool

```sql
SELECT seq, event_id, <the columns the event needs> FROM outbox WHERE published_at IS NULL ORDER BY seq LIMIT 100 FOR UPDATE SKIP LOCKED;
UPDATE outbox SET published_at = now(), publish_attempts = publish_attempts + 1 WHERE tenant_id = $1 AND event_id = $2;
```

The system role has the `UPDATE` grant on exactly those two columns, and `outbox_guard` still limits what they may become. `seq` has gaps after rollbacks and, being global, shows a tenant gaps where other tenants' events took numbers; it can commit out of order, so consumers must order by `aggregate.version`. A later migration may give the relay its own role.

### Authenticate a token, on the API pool

```sql
SELECT tenant_id, principal_id FROM resolve_token($1, $2);   -- $1: the 32 bytes of SHA-256(token), $2: the audience
```

Hash the presented token with SHA-256 in the API and pass the 32 bytes. Zero rows covers unknown, expired, revoked, wrong audience, disabled owner and disabled tenant alike, so the API cannot tell the caller which it was. With the tenant known, open a tenant transaction, and the same check is available there as `SELECT tenant_id, principal_id FROM active_api_tokens WHERE token_hash = $1 AND audience = $2` for that tenant's tokens. Recording `last_used_at` is an `UPDATE` in a tenant transaction.

### Check that an approval still counts (`tests/approvals.sql`), in a tenant transaction

```sql
SELECT count(*) FROM approvals
 WHERE tenant_id = $1 AND job_id = $2 AND decision = 'approve' AND pr_head_sha = $current_head
   AND invalidated_at IS NULL AND expires_at > now();
```

## What the tests assume of the storage crate

- The domain's hash function reproduces the two published vectors.
- Every method takes a tenant scope, opens its transaction with the setting, and puts the tenant in every `WHERE` and every join. The database now hides other tenants' rows, but a wrong setting is still a wrong answer.
- The isolation tests of `factory-storage` connect as the **application login**, never as the owner or a superuser: those silently bypass the policies, and a test that does not connect as the login proves nothing. The readiness query is the guard.
- Fixtures that create tenants run as the owner. Fixtures that create rows in tenant tables run as the tenant login with the setting made, or as a superuser.
- The storage tests that need to tamper with a ledger row (the byte-flip test in `s1-storage-postgres`) must do it as a superuser with `SET session_replication_role = replica`, or as the owner with `ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_no_change` **and** with row security lifted for the table (`ALTER TABLE ledger_entries NO FORCE ROW LEVEL SECURITY`, then restore it): the owner sees no row under `FORCE`.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| A query that must return rows returns none, and there is no error | The setting was not made in this transaction, or it names another tenant. `SELECT current_setting('factory.tenant_id', true)` in the same transaction |
| `new row violates row-level security policy` on an insert | The row's `tenant_id` differs from the setting, or the setting is empty |
| `invalid input syntax for type uuid` on a tenant table | The setting holds something that is not a uuid |
| `permission denied for table stage_runs` on the system pool | The query reads a column the system role may not read. Name the columns |
| `permission denied for function resolve_token` | The login is not a member of `factory_resolver` |
| `must be owner of table` when running a migration | The migration ran as `factory_app` or another member. Run as the owner |
| Migration 14 says to run as a superuser or the creator of `factory_lookup` | The migration role did not create the groups. See [migration-safety.md](migration-safety.md) |
| `ledger_entries_hash_matches_document` on the first insert | The hash formula differs: prefix on the previous hash, a newline, or the canonical text that was hashed is not the text that was stored |
| `ledger_entries_document_matches_columns` | A column was filled from a different value than the JSON, or the timestamp has a different instant |
| Inserts into `audit_events` queue up | Transactions write audit events early and then continue for a long time. Write them last |
| A claim returns nothing although a stage run is `READY` | `not_before` is in the future, the job is not `ACTIVE`, or another claimer holds the row |
| `attempts_live_attempt_has_current_epoch` at commit | The attempt was created at an old epoch, or the stage run was not moved to `RUNNING` with `lease_epoch + 1` in the same transaction |
