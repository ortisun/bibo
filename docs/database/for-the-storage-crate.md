# Notes for the storage crate

- Status: written for the engineer who builds `s1-storage-postgres`, revised for the ports v1.1 store ([ADR 0014](../adr/0014-ports-v1-1-claim-protocol-and-port-revision.md), [ports-v1.1](../architecture/ports-v1.1.md) section 5.2) by the work package `s1-database-port-alignment`. Every statement below is backed by a test in [`tests/`](tests/) or by the generated [`schema.rs`](../../crates/storage/src/schema.rs). Where something is a recommendation that was not run in Rust, it says so. No Rust code was run against this database.
- Form: how-to guide and reference. The method-by-method table is the part to implement from.
- The reference SQL is in `tests/lease.sql` (claim, start, heartbeat, due attempts, their moves), `tests/store_model.sql` (the other operations), `tests/webhook_delivery.sql`, `tests/outbox.sql`. Copy from there: those statements are the ones the tests ran, as the roles the storage crate uses.
- Why the rules are what they are: [tenancy.md](tenancy.md) and [constraints-and-indexes.md](constraints-and-indexes.md).

## Prerequisites

- The migrations applied (see [running.md](running.md)). The newest is migration 18; `Store::schema_version` is `SELECT count(*) FROM __diesel_schema_migrations` (Diesel's own version is 14 digits and `SchemaVersion` is 32 bits), and the code refuses to start when it is behind the count it was built for.
- **Three logins**, created by the deployment, never by the application. The migrations create the five groups as `NOLOGIN` roles and set no password:

  ```sql
  CREATE ROLE factory_api    LOGIN PASSWORD '...' IN ROLE factory_api_app, factory_resolver;  -- the API process (not factory_app: migration 20)
  CREATE ROLE factory_worker LOGIN PASSWORD '...' IN ROLE factory_app;                    -- tenant pool of the workflow and worker
  CREATE ROLE factory_engine LOGIN PASSWORD '...' IN ROLE factory_system;                 -- system pool of the workflow only
  ```

  Do not use `NOINHERIT`: a policy and a grant reach a login through its membership, and a `NOINHERIT` login would need `SET ROLE` first. **No login may be a member of both `factory_app` and `factory_system`**: permissive policies are combined with OR, and such a login reads every tenant's rows. The workflow process that needs both holds two logins and two pools.
- The owner role for fixtures that create tenants. The application role cannot insert into `tenants`, by design (onboarding is an owner action). Under `FORCE ROW LEVEL SECURITY` the owner sees no tenant row and can write none, so a fixture that needs rows in tenant tables writes them as `factory_app` with the setting made, or as a superuser. See [tenancy.md](tenancy.md).

In this document **T** is the tenant pool (`factory_worker`, or `factory_api` inside a `Tx`), **S** the system pool (`factory_engine`), **A** the API pool outside any `Tx`.

## What the storage crate must do, in order

1. **Two pools, two logins.** `Store::begin` uses the tenant login. `Store::begin_system` uses the system login. `resolve_token`, `resolve_installation` and `record_platform_audit` use the API login. `committed` uses the tenant login and a short tenant transaction.
2. **At start-up, for each pool,** run the query in [`tests/role_readiness.sql`](tests/role_readiness.sql) as that pool's login, and refuse to become ready unless the answer is right: not a superuser, no `BYPASSRLS`, owns no relation, in the right group and not in the other. The `rls` suite runs it as three real logins and as a superuser.

   | Pool | `superuser, bypassrls, owns_relations, tenant_group, system_group, resolver_group, lookup_group` |
   |---|---|
   | Tenant | `f, f, f, t, f, f, f` |
   | API | `f, f, f, t, f, t, f` |
   | System | `f, f, f, f, t, f, f` |

   Also read the migration count (both pools may) and refuse when it is behind the code.
3. **Every tenant statement runs inside a `Tx`, and a `Tx` starts like this**, as its first statement:

   ```sql
   SELECT set_config('factory.tenant_id', $1, true);   -- $1: the tenant's uuid in its text form, bound as a parameter
   ```

   The third argument `true` makes it local to the transaction. In Diesel: `diesel::sql_query("SELECT set_config('factory.tenant_id', $1, true)").bind::<Text, _>(tenant.to_string()).execute(&mut conn)` inside `AsyncConnection::transaction`. The extended protocol with a bound parameter was tried with `psql \bind`; `diesel-async` itself was not run.
4. **The `Tx` has no method that runs raw SQL or changes the setting.** No `Store` method runs a statement outside a `Tx`, apart from the three that have no tenant (`resolve_token`, `resolve_installation`, `record_platform_audit`, the last as a tenant-shaped transaction for the platform tenant).
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
| Lock with `FOR UPDATE` | It conflicts with the `KEY SHARE` lock that a ledger, audit or outbox insert takes on the row it points at. Use `FOR NO KEY UPDATE` | `lease` shell, "lock modes" |
| Write `lease_epoch`, `attempts_before_last_answer`, `created_at`, `finished_at` from the caller's clock | The epoch moves only in `start_attempt`, the window only when a person answers (S13), and the times come from `now()` in the statement | `lease` sections 7 to 9 |
| Pass a time computed in Rust to a lease, a deadline, a back-off or an expiry | Skew between hosts. Write `now() + $interval`. The database refuses a lease more than an hour ahead, but a few minutes of skew would pass | `lease` section 3 |
| Put the system role into `READ ONLY` mode | `SELECT ... FOR NO KEY UPDATE` is refused in a read-only transaction; the role already has no write grant | `store_model` section 11 |

## Rules that hold for every method

- **Lock order: job, then stage run, then attempt, then task node.** `start_attempt` share-locks the job and locks the run; the ledger append locks the job; a decision that moves a job and a stage run moves the job first. Two transactions that take their locks in this order cannot wait for each other. A deadlock that happens anyway is SQLSTATE `40P01`: map it to `Conflict` and let the caller read again.
- **Lock modes.** `FOR NO KEY UPDATE` on rows that will be changed or that other tables point at (stage runs, attempts, jobs, task nodes). `FOR NO KEY UPDATE SKIP LOCKED` for every finding query of the system role and for the relay. `FOR SHARE` on the job in `start_attempt` only, so that a pause or cancel of the job waits for the start (or the start sees the new status). Nothing uses `FOR UPDATE`.
- **The clock.** `now()` is the start of the transaction. Every comparison and every stored time in the recipes uses it, so a transaction sees one instant. `Tx::database_time` and `SystemTx::database_time` are `SELECT now()`; do not mix in `clock_timestamp()`. A transaction that stays open for seconds reads a stale `now()`: keep transactions short, which ADR 0007 already asks.
- **Times, versions and statuses are written by the caller's statement as the recipes show.** A terminal status sets `finished_at = now()` (stage runs), `ended_at = now()` (attempts), `terminal_at = now()` (jobs); `SUPERSEDED` also `superseded_at = now()`. A move into `READY` sets `not_before = now() + $delay` (zero when there is none).
- **An insert that is idempotent by id and content** is `INSERT ... ON CONFLICT (tenant_id, id) DO NOTHING RETURNING ...`. No row back means the id exists or another key clashed: read the row by id, compare its content, and answer `Inserted { created: false }` or `Constraint(IdReusedWithDifferentContent)`. A conflict on another key is a unique violation (`23505`) that the table below maps.

## Errors

Diesel reports SQLSTATE 23505, 23503 and 23514 as `UniqueViolation`, `ForeignKeyViolation` and `CheckViolation`, and gives the constraint name through `DatabaseErrorInformation::constraint_name()`. The triggers in these migrations set the constraint name on purpose, so the adapter can map precisely. Everything else arrives as `Unknown` with the message.

| SQLSTATE and constraint | What happened | `StoreError` |
|---|---|---|
| 0 rows updated by a `WHERE id = $1 AND version = $2` | Someone else changed the row | `Conflict` |
| 0 rows from a read or an update of a row that exists | The row belongs to another tenant, or the setting was not made. Indistinguishable by design (NT-TEN-05) | `NotFound` |
| 42501 "new row violates row-level security policy for table" | A write for a tenant other than the transaction's, or with no setting. A storage bug | `Internal(TenantSetting)`; never show it |
| 22P02 `invalid input syntax for type uuid` on a tenant table | The setting is not a uuid. A storage bug | `Internal(TenantSetting)` |
| 42501 "permission denied" | A missing grant, or a statement the role may not make | `Internal(PermissionDenied)` |
| 40P01 deadlock detected | Two transactions waited for each other | `Conflict` (read again) |
| 55P03 lock timeout, 57014 statement timeout | The adapter's own limits | `Unavailable`, and poison the transaction |
| 22003 `bigint out of range` on `lease_epoch + 1` | The epoch is at its maximum. Check `lease_epoch < 9223372036854775807` before the update and answer without it | `Constraint(LeaseEpochExhausted)` |
| 23505 `outbox_one_event_per_aggregate_version` | The event for this version already exists | `Conflict` (an idempotent replay) |
| 23505 `attempts_one_active_per_stage_run` | Another attempt is live | `Constraint(OneLiveAttempt)` |
| 23514 `attempts_within_stage_run_limit` | The run has used its attempts since the last human answer | `Constraint(AttemptLimit)` |
| 23505 `ledger_entries_pkey` | Someone appended at this position first | `Conflict` or `ChainBroken` |
| 23505 `jobs_tenant_id_webhook_delivery_id_key`, `jobs_tenant_id_idempotency_key_key` | The job already exists: read it by the origin and return it | `Inserted { created: false }` |
| 23505 `webhook_deliveries_*_key` | A repeated delivery | not an error: `ON CONFLICT DO NOTHING`, then the probe that says which key |
| 23505 `repositories_github_repository_id_key`, `api_tokens_token_hash_key` | Another tenant (or this one) holds the value | the same closed error as a missing object; never the message |
| 23505 `principals_tenant_id_github_user_id_key` | The GitHub user is recorded for the tenant under another id | `Constraint(ExternalReferenceTaken)` |
| 23505 `original_requests_tenant_id_job_id_revision_key`, `stage_runs_tenant_id_job_id_stage_kind_run_number_key`, `approvals_one_decision_per_head` | The same position taken by another id | `Constraint(IdReusedWithDifferentContent)` |
| 23505 `task_nodes_tenant_id_stage_run_id_task_key_key` | A task key used twice in the plan | `Constraint(DuplicateTaskKey)` |
| 23514 `task_node_dependencies_acyclic` | The edge closes a cycle | `Constraint(DependencyCycle)` |
| 23503, any composite key | A reference to another tenant's or another job's row, or to nothing | `TenantMismatch` or `NotFound` |
| 23503 on the key to the previous ledger entry | The predecessor does not exist | `ChainBroken` |
| 23503 `outbox_aggregate_type_transition_id_event_type_fkey` | The event names a transition that does not emit it | `Constraint(EventAggregateMismatch)` |
| 23514 `<table>_legal_transition`, `<table>_initial_state` | The engine tried a move the state machine does not allow (a domain bug) | `Constraint(IllegalStatusMove)` |
| 23514 `<table>_version_bump` | An update forgot `version = version + 1` (a storage bug) | `Internal(Unmapped)` |
| 23514 `stage_runs_terminal_is_immutable`, `attempts_terminal_is_immutable` | A write to a finished run or attempt | `Constraint(TerminalRowImmutable)` |
| 23514 `attempts_live_attempt_has_current_epoch` (at commit) | The attempt was created at another epoch than the run's | `LeaseFenced` |
| 23514 `stage_runs_live_attempt_needs_running_run` (at commit) | A run left `RUNNING` with a live attempt: the attempt was not ended in the same transaction (S04, S05, S06, S07, S19, S21) | `Constraint(IllegalStatusMove)` (a domain bug) |
| 23514 `stage_runs_not_before_only_when_ready`, `stage_runs_update_is_a_move_or_a_postponement`, `stage_runs_answer_window_is_derived` | A storage bug: a back-off outside `READY`, an update that is not a move or a postponement, or a write of the window | `Internal(Unmapped)` |
| 23514 `stage_runs_blocked_has_outcome`, `stage_runs_passed_has_outcome`, `stage_runs_skipped_has_outcome`, `stage_runs_failing_set_*` | The gate record does not fit the move (`stage_run_effects_rule`) | `Constraint(GateRecordRule)` |
| 23514 `attempts_failed_has_class`, `attempts_succeeded_has_output`, `attempts_cancelling_has_teardown` | The attempt end does not fit the move (`attempt_end_rule`) | `Constraint(AttemptEndRule)` |
| 23514 `attempts_sandbox_leaked_only_rises`, `attempts_sandbox_id_is_fixed` | A sandbox fact went backwards. Avoid the first by writing `sandbox_leaked = sandbox_leaked OR $leaked` | `Constraint(IdReusedWithDifferentContent)` |
| 23514 `task_nodes_running_has_attempt`, `task_nodes_idle_has_no_attempt`, `task_nodes_commit_iff_succeeded` | The task node record does not fit the move (`TaskNodeEffects`) | no code in `ConstraintRule`; see the open points below |
| 23514 `repositories_attestor_is_an_active_human` | The attestor is a service, disabled, unknown or of another tenant | no code in `ConstraintRule`; see the open points |
| 23514 `jobs_ledger_head_only_moves_forward` | A head pointer set back | `ChainBroken` |
| 23514 `ledger_entries_hash_matches_document`, `ledger_entries_document_matches_columns` | The entry does not match its hash or its document | `ChainBroken` |
| 23514 `outbox_aggregate_exists`, `outbox_aggregate_belongs_to_job`, `outbox_aggregate_has_reached_version` (at commit) | The event is inconsistent with its aggregate | `Constraint(EventAggregateMismatch)` |
| 23514 `audit_events_stage_run_needs_job` | A stage run named without a job | `Constraint(TextBounds)` or a domain bug |
| 42501 with "is append-only" | An update or delete of the ledger or audit log | `Internal(Unmapped)` (a bug) |

The deferred checks (`outbox_aggregate_*`, `attempts_live_attempt_has_current_epoch`, `stage_runs_live_attempt_needs_running_run`, `jobs_ledger_head_fk`) fire at `COMMIT`, not at the statement. Map errors from `commit()` as well.

Never pass the database's message or detail text to an API client. A unique violation names the key value in its detail, and the two keys that are global could tell a caller that another tenant already holds that repository or token. Log it, and return the closed error. NT-TEN-05 asks for the same answer for a missing object and a foreign one.

## Recipes

Each recipe names the test that ran it. "Tenant transaction" means a transaction that began with the `set_config` statement above, on the tenant pool.

### The claim, one recipe (`tests/lease.sql`; the two logins in `scripts/db-test.sh`, "rls")

**Step 1, `SystemTx::find_claim_candidates(limit)`, a system transaction.** Identifiers and the version only; the system role reads named columns.

```sql
SELECT s.tenant_id, s.job_id, s.id, s.version, s.not_before
  FROM stage_runs s
  JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE'
 WHERE s.status = 'READY' AND s.not_before <= now()
 ORDER BY s.not_before, s.id
 LIMIT $1
 FOR NO KEY UPDATE OF s SKIP LOCKED;
```

Then `finish`, which ends the transaction and releases the locks. A candidate is a hint. A stage run has no lease, so nothing here reads one. The index is `stage_runs_claim_order_idx` (plan in [query-plans.md](query-plans.md)).

**Step 2, `AttemptOps::start_attempt`, a tenant transaction for the candidate's tenant.** The sequence is (the engine adds its outbox event and audit record to the same transaction):

```sql
SELECT job_id FROM stage_runs WHERE tenant_id = $1 AND id = $2;                 -- the job never changes
SELECT status FROM jobs WHERE tenant_id = $1 AND id = $job FOR SHARE;           -- 1. lock the job
SELECT status, version, lease_epoch, max_attempts, attempts_before_last_answer,
       (not_before <= now()) AS due,
       (SELECT coalesce(max(attempt_number), 0) FROM attempts a
         WHERE a.tenant_id = s.tenant_id AND a.stage_run_id = s.id) AS last_number
  FROM stage_runs s WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE;         -- 2. lock the run
-- decide, in this order: no row: NotFound. status <> 'READY' or version <> $expected: Conflict.
-- job status <> 'ACTIVE': NotReady(JobNotActive). not due: NotReady(BackingOff).
-- lease_epoch = 9223372036854775807: Constraint(LeaseEpochExhausted).
-- last_number + 1 - attempts_before_last_answer > max_attempts: Constraint(AttemptLimit).
UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, version = version + 1
 WHERE tenant_id = $1 AND id = $2 AND version = $expected AND status = 'READY'
RETURNING lease_epoch, version;                                                 -- 3. S03
INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch,
                      lease_expires_at, deadline_at)
VALUES ($1, $attempt, $job, $2, $last_number + 1, $worker, $granted_epoch,
        now() + $lease_ttl, now() + $attempt_timeout)
RETURNING ...;                                                                  -- 4. the attempt, STARTING
```

Why each part:

- The job is share-locked so that a pause or cancel of the job (`FOR NO KEY UPDATE`) waits for this decision, or this decision sees the new status. A ledger or outbox insert (`KEY SHARE` on the job) does not wait; the `lease` shell run shows both.
- The decision is made from what was read under the locks, so the error is the one the port names. The database refuses the same things if the code is wrong: the compare and swap, the trigger that lets the epoch rise only with `READY` to `RUNNING`, the unique index of one live attempt, the attempt numbering and limit triggers, and the deferred check that a live attempt holds the run's current epoch.
- **Two workers can find the same candidate.** The lock of step 1 lasts only to the end of its transaction. The second to reach step 2 waits on the run's lock, then reads `RUNNING` and gets `Conflict`. The `rls` suite runs 12 rounds of four workers through two real logins (the sequence above in psql, with `\gset` and `\if`): in about half the rounds more than one worker had the same candidate, and every round ended with exactly one winner and one live attempt at epoch 1.
- `attempts_before_last_answer` is how many attempts came before the last human answer. The database sets it when the run moves from `WAITING_FOR_HUMAN` to `READY` (S13). The numbers of attempts keep rising (`last_number + 1`); only the limit counts from the window. This is INV-10 and `G_RETRY_ALLOWED`.

### Retry and back-off (S05, S13, S17): nothing waits for a lease

The attempt ends and the run moves back to `READY` in one tenant transaction, in either order of statements:

```sql
UPDATE attempts SET status = 'FAILED', failure_class = $class, ended_at = now(), version = version + 1
 WHERE tenant_id = $1 AND id = $attempt AND version = $v AND lease_epoch = $epoch AND status = 'RUNNING';   -- A05
UPDATE stage_runs SET status = 'READY', not_before = now() + $delay, version = version + 1
 WHERE tenant_id = $1 AND id = $run AND version = $v2 AND status = 'RUNNING';                                -- S05
```

The failed attempt may still show a lease that has not lapsed; it is terminal, so it holds nothing. The next `find_claim_candidates` sees the run as soon as `not_before` passes. A run that leaves `RUNNING` with a live attempt is refused at commit (`stage_runs_live_attempt_needs_running_run`); `SUPERSEDED` is exempt because its attempts are asked to cancel and take their grace period. Tested in `lease` section 9.

### `postpone_stage_run`

```sql
UPDATE stage_runs SET not_before = now() + $delay, version = version + 1
 WHERE tenant_id = $1 AND id = $2 AND version = $expected AND status = 'READY' RETURNING version;
```

Zero rows: read the run; `Conflict` if it changed, `NotFound` if it is not visible. The database refuses a change of `not_before` on a run that is not `READY`, and any other change of a run that keeps its status except a raised `max_attempts` (`lease` section 10).

### Renew a lease (`AttemptOps::heartbeat`), in a tenant transaction

```sql
UPDATE attempts SET lease_expires_at = now() + $ttl, last_heartbeat_at = now()
 WHERE tenant_id = $1 AND id = $attempt AND lease_owner = $worker AND lease_epoch = $epoch
   AND status IN ('STARTING', 'RUNNING', 'CANCELLING') AND lease_expires_at > now()
RETURNING status, lease_expires_at, deadline_at;
```

Zero rows: read the attempt. A terminal status is `Conflict`; anything else (wrong worker, wrong epoch, lapsed lease) is `LeaseFenced`. A lapsed lease belongs to the sweeper and the heartbeat cannot revive it. `CANCELLING` renews and the status read back tells the worker to tear down. A heartbeat leaves `version` alone ([ADR 0038](../adr/0038-a-heartbeat-renews-the-lease-and-leaves-the-version.md)): `version` counts changes of state, so a cancel or another versioned move of a running attempt does not race its heartbeat. The sweeper's move of a lapsed lease is guarded by the database clock in its own `UPDATE` (`lease_expires_at < now()`), and a heartbeat never renews a lapsed lease. Tested in `lease` sections 4 and 12.

### Due attempts and their moves (`SystemTx::find_due_attempts`, `transition_attempt` for A07, A06, A10)

Step 1, a system transaction, one of three queries by `DueReason` (each has its own partial index):

```sql
-- LeaseExpired (A07)
SELECT tenant_id, job_id, stage_run_id, id, version, lease_epoch FROM attempts
 WHERE status IN ('STARTING', 'RUNNING') AND lease_expires_at < now()
 ORDER BY lease_expires_at LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED;
-- DeadlinePassed (A06): the same with  deadline_at < now()  ORDER BY deadline_at
-- TeardownDeadlinePassed (A10):
SELECT ... FROM attempts WHERE status = 'CANCELLING' AND teardown_deadline_at < now()
 ORDER BY teardown_deadline_at LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED;
```

An attempt can be due for two reasons at once (lease and deadline both past); the engine takes the first it reads and the compare and swap of the other then moves nothing. A `CANCELLING` attempt with a lapsed lease is due only for the teardown deadline.

Step 2, a tenant transaction per tenant found, for each attempt, with the version and the epoch the finder read:

```sql
UPDATE attempts SET status = 'LEASE_LOST', ended_at = now(), version = version + 1          -- A07
 WHERE tenant_id = $1 AND id = $2 AND version = $3 AND lease_epoch = $4
   AND status IN ('STARTING', 'RUNNING') AND lease_expires_at < now();
-- A06: status = 'TIMED_OUT' ... AND deadline_at < now()
-- A10: status = 'CANCELLED', sandbox_leaked = true (when removal cannot be confirmed) ... AND status = 'CANCELLING' AND teardown_deadline_at < now()
```

The system role cannot write: an `UPDATE` of an attempt as `factory_system` is `42501` (`lease` section 11). The same transaction then takes the stage run's move (`S05`, `S06` or `S07`, by the retry rules) and the ledger and event. Tested in `lease` section 11 and, as the system login, in `rls` section 4.

### The blocked stage run (S21) and the reauthorization wait (S22)

**S21, `RUNNING` to `BLOCKED`**: one tenant transaction ends the attempt `FAILED` with class `SANDBOX_ERROR` or `TOOL_ERROR` (A02 from `STARTING`, A05 from `RUNNING`) and moves the run, recording the BLOCKED gate record:

```sql
UPDATE attempts SET status = 'FAILED', failure_class = $class, ended_at = now(), version = version + 1 WHERE ...;
UPDATE stage_runs SET status = 'BLOCKED', gate_outcome = 'BLOCKED', gate_report_sha256 = $report, version = version + 1
 WHERE tenant_id = $1 AND id = $run AND version = $v AND status = 'RUNNING';
```

The database refuses `BLOCKED` without the `BLOCKED` outcome and the move without ending the attempt. Nothing retries: the run leaves `READY`'s claim set. **S22, `READY` to `WAITING_FOR_HUMAN`**: a plain move; no attempt is created. The answer (S13) moves it back to `READY` and records the window. Tested in `lease` section 14 and `statuses` section 5.

### Locking

Use `FOR NO KEY UPDATE`, never `FOR UPDATE`, when you lock a job, a stage run, an attempt or a task node. A ledger, audit or outbox insert takes a `KEY SHARE` lock on the rows it points at, and `FOR UPDATE` conflicts with that. The `lease` shell run holds one stage run `FOR NO KEY UPDATE` and another `FOR UPDATE`, both as the system role, for two seconds, then appends a ledger entry for each as the tenant role with a 500 ms lock timeout. The first append goes through. The second fails with a lock timeout. The same run holds a job `FOR SHARE`: a ledger append goes through and a change of the job waits. The relay locks the outbox with `FOR NO KEY UPDATE SKIP LOCKED` too; nothing points at the outbox, so the two modes would behave alike, and one rule is easier to keep. Diesel has `for_no_key_update()` and `for_share()`.

### One decision, one transaction (`tests/outbox.sql`, section 5), a tenant transaction

```text
BEGIN;
  SELECT set_config('factory.tenant_id', $tenant, true);   -- first
  UPDATE jobs SET status = ..., version = version + 1
   WHERE tenant_id = $1 AND id = $2 AND version = $3;      -- one compare and swap; 0 rows: Conflict
  INSERT INTO ledger_entries (...) ...;                    -- hash computed by the domain code
  UPDATE jobs SET ledger_head_sequence = ..., ledger_head_hash = ... WHERE tenant_id = $1 AND id = $2;  -- no version bump
  INSERT INTO outbox (...) ...;                            -- names the transition, announces the new version
  INSERT INTO audit_events (...) ...;                      -- last: it holds a per-tenant lock until commit
COMMIT;
```

The ledger entry and the event may come before the job update, because the checks that span rows are deferred. If any statement fails, nothing remains: the suite injects a fault before and after the event insert and checks the job, the ledger and the outbox each time.

An outbox event announces `aggregate.version` after the change, which is what `transition_*` returned. The database refuses an event whose aggregate has not reached the announced version (`outbox_aggregate_has_reached_version`). It does not refuse one that announces an older version than the row now has.

**An append does not change the job's version** (migration 17). `append_ledger_entry` returns the chain head and no version, and `transition_job` takes the version the caller read; if the append bumped the version, a transition after an append in the same transaction would be a `Conflict` the caller could not foresee. The head pointer moves without a bump; a head move together with any other change of the job still raises the version by one, and a head move that raises it by one is still accepted. The head never moves back (`store_model` section 4). **This differs from the wording of ADR 0008** ("the same compare-and-swap as any other state") and is a decision for a person; the chain stays linear because the primary key of `ledger_entries` and the key to the predecessor allow one entry at each position.

### Append a ledger entry, in a tenant transaction

1. Build the entry and its RFC 8785 canonical JSON without `entry_hash`. Compute `entry_hash` as `sha256:` plus the hex of SHA-256 over `prev_entry_hash`, a newline and the canonical text. Use the vectors in [ledger-and-audit.md](ledger-and-audit.md) as your first test.
2. Lock the job row `FOR NO KEY UPDATE`, read the head (`ledger_head_sequence`, `ledger_head_hash`) and check the chain rules against it.
3. Insert with `canonical_json` set to that exact text, the queryable columns filled from the same values, and `prev_entry_hash` set. Leave `prev_sequence` out.
4. Move the head: `UPDATE jobs SET ledger_head_sequence = $n, ledger_head_hash = $h WHERE tenant_id = $1 AND id = $2 AND ledger_head_sequence = $n - 1`. Zero rows: `Conflict`.

### Receive a webhook (`tests/webhook_delivery.sql`, `tests/store_model.sql` section 6)

1. **Before any tenant is known,** verify the signature, then call `resolve_installation(installation_id, github_repository_id)` on the API pool, outside a `Tx`. Zero rows: the installation or repository is unknown, disabled, or the pair does not belong together, and the caller is not told which. Record a `webhook.rejected` audit event with `record_platform_audit` (below) and answer as for any bad request.
2. **With the tenant,** open a tenant transaction and:

```sql
INSERT INTO webhook_deliveries (...) VALUES (...) ON CONFLICT DO NOTHING RETURNING id;
-- a row: Recorded(id). No row: a repeat. Ask which key found it, in one statement:
SELECT CASE WHEN delivery_id = $d THEN 'delivery_id' WHEN body_sha256 = $b THEN 'body' ELSE 'semantic' END
  FROM webhook_deliveries
 WHERE tenant_id = $1 AND (delivery_id = $d OR body_sha256 = $b OR semantic_key = $s)
 ORDER BY (delivery_id = $d) DESC, (body_sha256 = $b) DESC LIMIT 1;
-- Duplicate(DeliveryId | Body | Semantic). Acknowledge and stop. Otherwise, in the same transaction:
INSERT INTO jobs (..., webhook_delivery_id) VALUES (..., $delivery_row_id) ON CONFLICT DO NOTHING RETURNING id;
```

Fifty concurrent copies of one delivery give one new row and no error in any of them. The three conflicts are absorbed by the same `ON CONFLICT DO NOTHING`; the probe uses the three unique indexes in one bitmap-or plan.

### `insert_job` found by its origin (`store_model` section 5)

`INSERT INTO jobs (...) VALUES (...) ON CONFLICT DO NOTHING RETURNING id`. A row back: created. No row: read the job by id; if none, read it by `webhook_delivery_id` or by `idempotency_key` (the origin); if still none, the clash was on `correlation_id` alone and the id was never used: `Constraint(IdReusedWithDifferentContent)`. A job found by id with other content (compare repository, requester, mode, level, scope, correlation id) is `Constraint(IdReusedWithDifferentContent)`; one found by the origin under another id is returned as the first job.

### `record_audit` and `record_platform_audit` (`store_model` section 8)

```sql
INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason,
                          policy_hash, job_id, stage_run_id, correlation_id)
VALUES (...) ON CONFLICT (tenant_id, event_id) DO NOTHING RETURNING sequence, created_at, hash;
```

A replay takes no sequence number, so the chain has no gap. No row back: read the event by id and compare its fields. The database assigns the sequence, the time and the hash. `job_id` may be NULL (a rejected issue, FR-002); `stage_run_id` needs a `job_id`. **The platform audit path** is the same statement in a tenant-shaped transaction on the API pool, with the setting `00000000-0000-0000-0000-000000000001` (the platform tenant created by migration 2): `actor_type = 'anonymous'`, `job_id` NULL. The composite key refuses a job (the platform tenant has none), the policy refuses a tenant session writing for the platform and the platform session writing for a tenant, and no tenant session reads the events. The platform tenant is an ordinary tenant to the database; only the port keeps `TenantScope::new` from being called with it (ST-13). Reading the platform trail is an owner action.

### The tenant-scoped artifact read (`store_model` section 9)

`ArtifactStore::get` and `exists` open a short tenant transaction for the scope they were given and ask `SELECT size_bytes FROM artifacts WHERE tenant_id = $1 AND content_sha256 = $2`; no row is `NotFound` / `false`, for a hash the tenant never indexed and for one that only another tenant holds. Only then do they read the blob and hash it again. `index_artifact` is `INSERT ... ON CONFLICT (tenant_id, content_sha256) DO NOTHING RETURNING ...`; the size is required (`NOT NULL`), so the adapter takes it from the blob it just stored (`ArtifactRef.size_bytes` is optional in the port).

### Consume an event (`tests/outbox.sql`, function `dbtest.consume`), in a tenant transaction

```sql
INSERT INTO inbox (tenant_id, consumer, event_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING RETURNING event_id;
-- no row returned: already handled. Otherwise apply the effect in the same transaction.
```

### Relay the outbox, on the system pool

```sql
SELECT seq, event_id, <the columns the event needs> FROM outbox WHERE published_at IS NULL ORDER BY seq LIMIT 100 FOR NO KEY UPDATE SKIP LOCKED;
UPDATE outbox SET published_at = now(), publish_attempts = publish_attempts + 1 WHERE tenant_id = $1 AND event_id = $2;
```

The system role has the `UPDATE` grant on exactly those two columns, and `outbox_guard` still limits what they may become. `seq` has gaps after rollbacks and, being global, shows a tenant gaps where other tenants' events took numbers; it can commit out of order, so consumers must order by `aggregate.version`. A later migration may give the relay its own role.

### Authenticate a token, on the API pool

```sql
SELECT tenant_id, principal_id FROM resolve_token($1, $2);   -- $1: the 32 bytes of SHA-256(token), $2: the audience
```

Hash the presented token with SHA-256 in the API and pass the 32 bytes. Zero rows covers unknown, expired, revoked, wrong audience, disabled owner and disabled tenant alike, so the API cannot tell the caller which it was. With the tenant known, open a tenant transaction, and the same check is available there as `SELECT tenant_id, principal_id FROM active_api_tokens WHERE token_hash = $1 AND audience = $2` for that tenant's tokens. Recording `last_used_at` is an `UPDATE` in a tenant transaction.

### Record and check an approval (`store_model` section 10)

```sql
INSERT INTO approvals (tenant_id, id, job_id, stage_run_id, decision, approver_principal_id, approver_github_user_id, approver_designation,
                       allowlist_version_hash, policy_hash, reason, channel, expires_at, pr_head_sha, tree_hash, base_sha, evidence_manifest_hash, spec_version)
SELECT p.tenant_id, $id, $job, $run, $decision, p.id, p.github_user_id, $designation, ..., now() + $valid_for, $head, $tree, $base, $manifest, $spec
  FROM principals p WHERE p.tenant_id = $1 AND p.id = $approver AND p.kind = 'human' AND p.disabled_at IS NULL
ON CONFLICT (tenant_id, id) DO NOTHING RETURNING id;
```

The GitHub user id comes from the principal and the expiry from the database clock. No row back: a replay, or the principal is not an active human; read the approval by id, then the principal, to tell which. `valid_approvals(job, head)`: `decision = 'approve' AND pr_head_sha = $head AND invalidated_at IS NULL AND expires_at > now()`. `invalidate_approvals(job, reason)`: `UPDATE approvals SET invalidated_at = now(), invalidation_reason = $reason WHERE tenant_id = $1 AND job_id = $2 AND invalidated_at IS NULL AND expires_at > now()`; the row count is the answer. The uniqueness is per head: a decision with no head (pause, cancel) can repeat.

## The Store methods of ports v1.1, one by one

Columns are those of [`schema.rs`](../../crates/storage/src/schema.rs). Every method puts `tenant_id` in its `WHERE`. "Backed by" names what the database enforces if the code is wrong; the suite that proves it is in brackets.

### `Store` and the two transaction openers

| Method | SQL shape | Pool | Backed by |
|---|---|---|---|
| `fidelity` | none (`real`) | none | none |
| `begin(TenantScope)` | `BEGIN; SELECT set_config('factory.tenant_id', $1, true)` | T | policy `tenant_isolation` on 17 tables [`rls`] |
| `begin_system(SystemScope)` | `BEGIN` (not `READ ONLY`); no setting | S | column grants and the policies `system_find`, `system_lock` [`rls` section 4] |
| `resolve_token` | `SELECT tenant_id, principal_id FROM resolve_token($1, $2)` | A | `SECURITY DEFINER` function owned by `factory_lookup`, execute for `factory_resolver` only [`rls`, `tokens`] |
| `resolve_installation` | `SELECT tenant_id, repository_id FROM resolve_installation($1, $2)` | A | the same; unique `github_repository_id` [`rls`, `tenancy`] |
| `record_platform_audit` | the audit insert above, in a tenant-shaped transaction for the platform tenant | A | platform tenant row; policy; composite key to `jobs`; audit chain trigger [`store_model` section 8] |
| `committed(scope, Witness)` | `SELECT EXISTS (SELECT 1 FROM outbox WHERE tenant_id = $1 AND event_id = $2)`, or the same on `audit_events` | T | primary key of `outbox`; unique `(tenant_id, event_id)` of `audit_events` [`plans`: both are index scans] |
| `schema_version` | `SELECT count(*) FROM __diesel_schema_migrations` | T or S | `SELECT` grant on that table [`privileges`, `rls`] |

### `SystemTx` (read only in effect)

| Method | SQL shape | Pool | Backed by |
|---|---|---|---|
| `database_time` | `SELECT now()` | S | none needed |
| `find_claim_candidates(limit)` | the step 1 query above | S | no write grant; `FOR NO KEY UPDATE` needs the `UPDATE (updated_at)` grant and policy `system_lock` (`WITH CHECK (false)`); index `stage_runs_claim_order_idx` [`lease`, `rls`, `plans`] |
| `find_due_attempts(reason, limit)` | the three queries above | S | the same, on `attempts`; indexes `attempts_deadline_idx`, `attempts_teardown_idx`, and for an expired lease the live attempts through `attempts_deadline_idx` or `attempts_one_active_per_stage_run` (no index is keyed on the lease since migration 19, so that a renewal is a heap-only update) [`lease` sections 11 and 14, `rls`, `plans`] |
| `finish` | `COMMIT` or `ROLLBACK` | S | none |

### `Tx`

| Method | SQL shape | Pool | Backed by |
|---|---|---|---|
| `database_time` | `SELECT now()` | T | none needed |
| `commit` | `COMMIT`. A lost answer is `CommitOutcomeUnknown`; the caller asks `committed` | T | the deferred checks fire here [`outbox`, `lease`] |
| `rollback` | `ROLLBACK` | T | none |

### `JobOps`

| Method | SQL shape | Backed by |
|---|---|---|
| `insert_job` | `INSERT INTO jobs (...) ON CONFLICT DO NOTHING RETURNING id`, then the lookups above | primary key; unique `(tenant_id, idempotency_key)`, `(tenant_id, webhook_delivery_id)`, `(tenant_id, correlation_id)`; composite keys to `repositories`, `principals`; `jobs_pipeline_scope_check`; initial-state trigger [`store_model` section 5] |
| `get_job` | `SELECT ... FROM jobs WHERE tenant_id = $1 AND id = $2` | policy [`rls`] |
| `list_jobs(filter, after, limit)` | `... WHERE tenant_id = $1 [AND status = ANY($s)] [AND repository_id = $r] [AND (created_at, id) < ($c, $i)] ORDER BY created_at DESC, id DESC LIMIT $n` | `jobs_listing_idx`, `jobs_open_idx`, `jobs_repository_listing_idx` [`plans`] |
| `transition_job` | `UPDATE jobs SET status = $to, version = version + 1, terminal_at = CASE WHEN $terminal THEN now() END WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = $from` | status trigger; `jobs_terminal_check`; `jobs_version_bump` [`statuses`, `terminal_rows`, `store_model` section 4] |
| `update_job_facts` | `UPDATE jobs SET policy_hash = coalesce(policy_hash, $p), normalized_request_sha256 = coalesce(normalized_request_sha256, $n), version = version + 1 WHERE ... AND version = $3`. Write-once is the adapter's: the database does not refuse a changed fact (see the open points) | hash `CHECK`s; composite key to `artifacts` |

### `RequestOps`, `DeliveryOps`, `RepositoryOps`

| Method | SQL shape | Backed by |
|---|---|---|
| `record_original_request` | `INSERT INTO original_requests (...) ON CONFLICT (tenant_id, id) DO NOTHING RETURNING id` | unique `(tenant_id, job_id, revision)`; hash must match the text (`original_requests_hash_matches_text`); update, delete and truncate refused [`store_model` section 7] |
| `get_original_request(job, revision)` | `... WHERE tenant_id = $1 AND job_id = $2 [AND revision = $3] ORDER BY revision DESC LIMIT 1` | `original_requests_tenant_id_job_id_revision_key` [`plans`] |
| `record_delivery` | the insert and the probe above | unique `(tenant_id, delivery_id)`, `(tenant_id, body_sha256)`, `(tenant_id, semantic_key)` [`webhook_delivery`, `store_model` section 6, `plans`] |
| `get_repository` | `SELECT ... FROM repositories WHERE tenant_id = $1 AND id = $2` | policy |
| `record_protection_preflight` | `UPDATE repositories SET protection_preflight_passed = $p, version = version + 1 WHERE tenant_id = $1 AND id = $2 AND version = $3`. `autonomy_ceiling` is left alone: it holds the ceiling an organization admin set. The effective level is `CASE WHEN protection_preflight_passed THEN autonomy_ceiling ELSE 'L0' END` (ADR 0009, default 3), computed on read, so a later passing preflight restores what the admin set | column grant; `autonomy_ceiling` check; `repositories_version_bump` [`privileges`] |

### `StageRunOps`

| Method | SQL shape | Backed by |
|---|---|---|
| `insert_stage_run` | `INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number, max_attempts, rework_of_stage_run_id) ON CONFLICT (tenant_id, id) DO NOTHING RETURNING id` | unique `(tenant_id, job_id, stage_kind, run_number)`; initial state `PENDING`; composite key for `rework_of` [`store_model` section 7] |
| `get_stage_run` | `SELECT ... FROM stage_runs WHERE tenant_id = $1 AND id = $2` (no lease columns: a run has none) | policy |
| `list_stage_runs(job)` | `... WHERE tenant_id = $1 AND job_id = $2 ORDER BY created_at, id` | `stage_runs_tenant_id_job_id_stage_kind_run_number_key` [`plans`] |
| `transition_stage_run` | `UPDATE stage_runs SET status = $to, version = version + 1, finished_at = ..., superseded_at = ..., not_before = now() + $delay (into READY), stage_contract_sha256 = $c (S01), gate_outcome = $o, gate_report_sha256 = $r, failing_set_sha256 = $f (gate transitions) WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = $from`. Not for S03 | status trigger; `stage_runs_passed_has_outcome`, `_skipped_has_outcome`, `_blocked_has_outcome`, `_failing_set_*`; `stage_runs_terminal_is_immutable`; `stage_runs_live_attempt_needs_running_run`; S13 sets the window [`statuses`, `terminal_rows`, `store_model` section 1, `lease` sections 8, 9, 14] |
| `postpone_stage_run` | the postponement above | `stage_runs_not_before_only_when_ready`; `stage_runs_update_is_a_move_or_a_postponement` [`lease` section 10] |

### `AttemptOps`

| Method | SQL shape | Backed by |
|---|---|---|
| `start_attempt` | the four-step sequence above | compare and swap; `stage_runs_lease_epoch_moves_with_claim`; `attempts_one_active_per_stage_run`; `attempts_numbered_in_sequence`; `attempts_within_stage_run_limit`; `attempts_live_attempt_has_current_epoch`; `attempts_lease_within_bound` [`lease` sections 1, 2, 7, 8; races in `lease` and `rls`] |
| `get_attempt` | `SELECT ... FROM attempts WHERE tenant_id = $1 AND id = $2` | policy |
| `list_attempts(stage_run)` | `... WHERE tenant_id = $1 AND stage_run_id = $2 ORDER BY attempt_number` | `attempts_tenant_id_stage_run_id_attempt_number_key` [`plans`] |
| `heartbeat` | the renewal above | `attempts_lease_within_bound`; terminal attempts immutable [`lease` sections 3, 4, 12] |
| `transition_attempt` | `UPDATE attempts SET status = $to, version = version + 1, ended_at = now() (terminal), failure_class = $c (A02, A05), output_sha256 = $o (A04), teardown_deadline_at = now() + $grace (A08), sandbox_id, sandbox_leaked WHERE tenant_id = $1 AND id = $2 AND version = $3 AND lease_epoch = $epoch AND status = $from` | status trigger; `attempts_failed_has_class`, `_succeeded_has_output`, `_cancelling_has_teardown`; `attempts_terminal_check`; composite key for the output artifact [`lease`, `terminal_rows`] |
| `record_sandbox` | `UPDATE attempts SET sandbox_id = $s, sandbox_leaked = sandbox_leaked OR $leaked, version = version + 1 WHERE tenant_id = $1 AND id = $2` (any status) | `attempts_sandbox_leaked_only_rises`, `attempts_sandbox_id_is_fixed`; the masked columns of the terminal guard [`lease` section 13] |

### `TaskNodeOps`, `StageArtifactOps`

| Method | SQL shape | Backed by |
|---|---|---|
| `insert_task_graph` | in one transaction: `INSERT INTO task_nodes (...)` for every node (one statement), then `INSERT INTO task_node_dependencies (...)` for every edge (one statement). A repeat for the same stage run: read the nodes first (lock the stage run `FOR NO KEY UPDATE` to serialize two writers) and compare the plan hash | unique `(tenant_id, stage_run_id, task_key)`; `task_node_dependencies_acyclic` (sees the earlier rows of its own statement); self-edge `CHECK`; composite keys; the plan must be an indexed artifact of the tenant [`store_model` section 3] |
| `get_task_node` | `SELECT ... FROM task_nodes WHERE tenant_id = $1 AND id = $2` | policy |
| `list_task_nodes(stage_run)` | `... WHERE tenant_id = $1 AND stage_run_id = $2 ORDER BY task_key` | `task_nodes_tenant_id_stage_run_id_task_key_key` [`plans`] |
| `task_dependencies(stage_run)` | `SELECT d.task_node_id, d.depends_on_task_node_id FROM task_nodes n JOIN task_node_dependencies d ON d.tenant_id = n.tenant_id AND d.task_node_id = n.id WHERE n.tenant_id = $1 AND n.stage_run_id = $2` (through the nodes: no index on the edges' `stage_run_id` is needed) | primary key of the edges [`plans`] |
| `transition_task_node` | `UPDATE task_nodes t SET status = $to, current_attempt_id = $a, commit_sha = $c, finished_at = ..., version = version + 1 FROM attempts a WHERE t.tenant_id = $1 AND t.id = $2 AND t.version = $3 AND a.tenant_id = t.tenant_id AND a.id = $fence_attempt AND a.lease_owner = $worker AND a.lease_epoch = $epoch AND a.status IN ('STARTING', 'RUNNING', 'CANCELLING')` for T02 to T05; without the join for the others. A fence is "live and the current epoch": the lease need not be unexpired (only `heartbeat` requires that) | status trigger; `task_nodes_running_has_attempt`, `_idle_has_no_attempt`, `_commit_iff_succeeded` [`store_model` section 3] |
| `link_stage_run_artifact` | `INSERT INTO stage_run_artifacts (...) ON CONFLICT (tenant_id, stage_run_id, direction, role) DO NOTHING RETURNING role`; no row: compare the hash | primary key; composite key to `artifacts` (index the artifact first); role pattern, so `human-answer-<n>` fits [`store_model` section 10] |
| `list_stage_run_artifacts` | `... WHERE tenant_id = $1 AND stage_run_id = $2 ORDER BY created_at, role` | primary key |
| `stage_runs_consuming(job, sha256)` | `SELECT stage_run_id FROM stage_run_artifacts WHERE tenant_id = $1 AND job_id = $2 AND content_sha256 = $3 AND direction = 'input'` | `stage_run_artifacts_hash_idx` [`plans`] |

### `ApprovalOps`, `LedgerOps`, `OutboxOps`, `AuditOps`, `ArtifactIndexOps`, `PrincipalOps`

| Method | SQL shape | Backed by |
|---|---|---|
| `record_approval` | the `INSERT ... SELECT` above | composite key to a human principal; `approvals_approve_is_bound`; expiry after creation; unique per head [`approvals`, `store_model` section 10] |
| `list_approvals(job)` | `... WHERE tenant_id = $1 AND job_id = $2 ORDER BY created_at` | `approvals_job_idx` |
| `valid_approvals(job, head)` | the query above | `approvals_job_idx` [`plans`] |
| `invalidate_approvals` | the update above | column grants; `approvals_guard` (one invalidation) [`approvals`] |
| `append_ledger_entry` | the append steps above | primary key and key to the predecessor; `ledger_entries_guard` (hash and document); no update, delete or truncate; head moves forward only [`ledger`, `store_model` section 4] |
| `ledger_head(job)` | `SELECT ledger_head_sequence, ledger_head_hash FROM jobs WHERE tenant_id = $1 AND id = $2` | `jobs_ledger_head_fk` (deferred) |
| `read_ledger(job, from, limit)` | `... WHERE tenant_id = $1 AND job_id = $2 AND sequence >= $3 ORDER BY sequence LIMIT $4` | primary key [`plans`] |
| `enqueue_event` | `INSERT INTO outbox (...) ON CONFLICT (tenant_id, event_id) DO NOTHING`; no row: compare | the foreign key to `state_machine_transitions`, `outbox_one_event_per_aggregate_version`, `outbox_aggregate_*` at commit [`outbox`] |
| `read_events(job, from, limit)` | `... WHERE tenant_id = $1 AND job_id = $2 AND seq >= $3 ORDER BY seq LIMIT $4` | `outbox_job_timeline_idx` [`plans`] |
| `record_audit` | the audit insert above | chain trigger; no update, delete or truncate [`audit`, `store_model` section 8] |
| `read_audit(filter, after, limit)` | `... WHERE tenant_id = $1 [AND job_id = $2] AND sequence > $3 ORDER BY sequence LIMIT $4` | primary key; `audit_events_job_idx` [`plans`] |
| `index_artifact` | `INSERT INTO artifacts (...) ON CONFLICT (tenant_id, content_sha256) DO NOTHING RETURNING ...` | primary key; composite key for the origin; both origin columns or neither; size required [`store_model` section 9] |
| `get_artifact_index(sha256)` | `SELECT ... FROM artifacts WHERE tenant_id = $1 AND content_sha256 = $2` | policy; primary key [`plans`] |
| `insert_principal` | `INSERT INTO principals (...) ON CONFLICT (tenant_id, id) DO NOTHING RETURNING id` | unique `(tenant_id, github_user_id)`; `kind` and GitHub id agree [`store_model` section 10] |
| `get_principal` | `SELECT ... FROM principals WHERE tenant_id = $1 AND id = $2` | policy |
| `find_principal_by_github_user` | `... WHERE tenant_id = $1 AND github_user_id = $2` | unique `(tenant_id, github_user_id)` |

## Open points the storage author will meet

These are the places where the database is as far as it goes and something outside it decides. None needs a stopgap value; each needs a decision.

1. **`RepositoryOps` cannot read or write the attestation.** The columns `bypass_attested_by_principal_id` and `bypass_attested_at` exist, with their rules, but `Repository` and `RepositoryOps` of ports-v1.1 have no field or method for them. The port needs `Repository.bypass_attestation` and a `record_bypass_attestation`.
2. **`ConstraintRule` has no code** for the task node record, the attestor, the live-attempt rule and the sandbox facts. The table above uses the nearest code and says so.
3. **`update_job_facts` is write-once in the port and not in the database.** ADR 0010 re-runs `INTAKE` when the source request changes, which would produce a new normalized request hash. If the port keeps "set once", re-intake has nowhere to put the new hash; if it does not, the adapter's check is the only one. A trigger would turn the port's rule into the data's, and was not added so as not to forbid re-intake.
4. **`index_artifact` with `ArtifactRef.size_bytes = None`.** The column is `NOT NULL` on purpose (quota and accounting need a size). The adapter takes the size from the blob it holds. If the port wants to index a blob it does not hold, it needs the size in `NewArtifactIndexEntry`.
5. **`ApprovalInvalidation` and `approval_binding.invalidated_by`** differ (the port has `ImageChange`; the policy lists a force push, a changed gate result and a removed approver). `invalidation_reason` is free text of 1 to 1000 characters, so the database accepts either; the closed set belongs to the port.
6. **A decision with no head can repeat.** `approvals_one_decision_per_head` applies when `pr_head_sha` is set. The port says "a second decision of the same approver, kind and head" is refused; for a pause or a cancel there is no head and the database allows a repeat, as a pause, resume and pause again needs.
7. **The effect text of `A07` in `state-machine.json`** says "increment lease_epoch to fence the old worker". ADR 0014 (R2) and the database say the epoch rises only when a run goes from `READY` to `RUNNING`; a lost lease needs no raise, because the attempt is terminal and a fence is current only for a live attempt at the run's epoch. The trigger would refuse a raise at A07. The text should follow the ADR.
8. **The ceiling the admin set and the ceiling the preflight allows are two facts and `repositories` has one column for the first.** `record_protection_preflight` therefore writes the boolean only, and the lower of the two is computed on read. If the port wants `Repository.autonomy_ceiling` to be the effective level, the adapter computes it; if it wants the preflight to lower the stored value, a passing preflight can no longer restore what the admin set.
9. **`list_jobs` by status** reads `jobs_open_idx` for open statuses and the listing index otherwise; a filter on closed statuses only (COMPLETED, FAILED) has no partial index and filters the listing. Not a problem at the sizes measured; add an index when a dashboard filters on them often.
10. **The migration `000500` header comment** says `FOR UPDATE SKIP LOCKED`. It is not edited (migrations are not amended once applied). The catalog comment on `stage_runs_claim_order_idx` and this document state the right mode.

## Diesel facts that differ from the usual

- **Composite primary keys.** Every tenant-owned table has `(tenant_id, id)` as its key, so `table.find((tenant, id))` is the only way to find by key. This is intended: a lookup by id alone does not compile.
- **No `joinable!` for composite foreign keys.** `diesel print-schema` writes `joinable!` only for single-column keys, so only the keys to `tenants` appear. Write joins with `.on(...)` and include the tenant in the condition.
- **Views are not in `schema.rs`.** `active_api_tokens`, `ledger_current_claims` and `ledger_assurance_levels` need a hand-written `table!` in `crates/storage/src/pg/`, or `sql_query`. Do not add them to `schema.rs`: the migrations test regenerates that file and compares it.
- **Functions are not in `schema.rs` either.** Declare `resolve_token` and `resolve_installation` with `diesel::define_sql_function!` or call them with `sql_query`.
- **Columns the database assigns.** Leave these out of the `Insertable` struct and the database fills them: `audit_events.sequence`, `created_at`, `prev_sequence`, `prev_hash`, `canonical_json`, `hash`; `ledger_entries.prev_sequence` and `inserted_at`; `outbox.seq` (`GENERATED ALWAYS`, a supplied value is an error); `stage_runs.attempts_before_last_answer`; `repositories.bypass_attested_at`. They are `NOT NULL` or derived, and the `BEFORE INSERT` trigger runs before the null check.
- **Generated order.** Diesel's `table!` for `outbox` lists `seq` first. It is an identity column and the application role needs no sequence privilege for it.
- **Prepared statements are safe across tenants.** A generic plan made for one tenant gives the next tenant its own rows, because the policy reads the setting when the statement runs. Tried with `plan_cache_mode = force_generic_plan`.

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
| `stage_runs_live_attempt_needs_running_run` at commit | A stage run was moved out of `RUNNING` and its live attempt was not ended in the same transaction |
| `attempts_within_stage_run_limit` right after a human answered | The answer did not move the run from `WAITING_FOR_HUMAN` to `READY` (S13), so the window did not restart |
| `jobs_version_bump` after an append | The update changed something besides the head pointer without raising the version by one |
| A `40P01` deadlock between a decision and a start | A transaction took its locks out of the order job, stage run, attempt, task node |

## From the review at realistic volume (`s1-database-review`, 2026-10-28)

Measured, with the numbers and the method in [performance.md](performance.md) and [operating-settings.md](operating-settings.md). Three changes belong to this crate; none is made here.

1. **Send the three transaction settings in one statement.** `start` in `tx.rs` sends `set_config('factory.tenant_id', ...)` and then a second `set_config` for the two timeouts. One statement, `SELECT set_config('factory.tenant_id', $1, true), set_config('statement_timeout', $2, true), set_config('lock_timeout', $3, true)`, does both: it saves one round trip, 24 microseconds on loopback and 0.3 to 1 ms across a network. The tenant must still be set before any other statement; it is.
2. **Run `resolve_token`, `resolve_installation` and `schema_version` inside a short transaction that sets the limits**, like every other call. They run today on a bare pooled connection with no `statement_timeout` and no `lock_timeout`.
3. **Make `refuses_a_role_that_bypasses_rls` delete a migration version the code embeds**, not the newest row of `__diesel_schema_migrations`. Once the schema is ahead of the code, the newest row is not one the code lists and the test stops proving that a database behind the code is refused (it failed for the earlier code at every schema from 15 on).

Also from the review: the claim slows when many READY runs belong to jobs that are not `ACTIVE` (finding F-01 of [../reviews/database-review.md](../reviews/database-review.md)); nothing for the crate to do, but a count of READY runs of non-active jobs is worth exporting as a metric.

