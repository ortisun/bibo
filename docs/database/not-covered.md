# What the database work does not cover

- Status: after the work package `s1-database-tenancy-and-state-sync`, updated by `s1-database-port-alignment` and by `s1-database-review` (2026-10-28, marked below). This list is part of the deliverable, so a reader does not mistake the tests for more than they prove.
- Form: reference.

## In short

1. Row-level security is on, and it stops a forgotten `WHERE`, not an attacker who can run SQL as a tenant login. The tenant setting is not a credential.
2. A transaction-mode pooler and PostgreSQL 17 were not run. `diesel-async` has run since `s1-storage-postgres` (the storage crate's tests, 63 of them, pass against a real server as the three real logins; [adr-0012-open-items.md](adr-0012-open-items.md)).
3. Nothing is ever deleted. **A retention and partitioning proposal exists** ([retention-and-partitioning.md](retention-and-partitioning.md)); none of it is built, and it names five decisions for a person.
4. The audit anchor, the hourly verifier and the Rust chain verifier do not exist, and the chain verifiers answer "sound" to a session set to the wrong tenant.
5. **Measured since `s1-database-review`, on one laptop with the client on the same machine:** the hot queries at 100,000 rows as the real logins ([performance.md](performance.md)), concurrency up to 16 clients, ninety seconds of churn. Not measured: a network between the application and the database, production hardware, a database that has run for months, more than 16 clients.
6. A superuser rewrite and a deleted audit tail get past the database.
7. Several limits are my sanity bounds, not policy figures.

The tables below give the detail.

## Decided later, on purpose

| Not covered | Where it is decided | Why it matters |
|---|---|---|
| **Retention and deletion.** Nothing deletes anything. The application role has no `DELETE`. `webhook_deliveries` should be trimmed at 30 days, the outbox needs a retention rule (ADR 0004), and `jobs` can never be deleted while ledger entries exist, because the ledger is append-only and points at them. | **Proposed, not built:** [retention-and-partitioning.md](retention-and-partitioning.md) (2026-10-28), with prototypes of a maintenance role, of partitioning and of the archive of a ledger range. It names five decisions for a person. | Storage grows without limit (about 400 KB per completed job, an estimate). A request for deletion of personal data has no path yet. |
| **Partitioning** of the outbox, the audit log and the ledger. | **Proposed, not built.** Prototyped on a scratch cluster: the outbox cannot be partitioned by time without weakening its keys; the ledger can, by range of `job_id`, after three changes; the audit log can only be cut by sequence range per tenant. See [retention-and-partitioning.md](retention-and-partitioning.md). | No table is near a size where partitioning helps (all hot queries are inside their budgets at 100,000 rows). The first partitioned table costs a rewrite of the ledger guard function, a new unique key and an update of five suites. |
| **Other database roles.** There are four groups (`factory_app`, `factory_system`, `factory_resolver`, `factory_lookup`). A maintenance role, a read-only role for the dashboard and a role for the verification job would each hold less. | With the services that need them. | The relay and the sweeper share `factory_system`, which can read the outbox and the claim columns. A dashboard that only reads would still need its own policies. |
| **Further loops of the system scope.** The policies list the claim, the sweep and the relay. A timer for paused jobs, a quota counter or a cleanup would need a migration and a line in the `rls` suite. | With the engine package. | An undeclared cross-tenant query fails with `permission denied`, which is the intended behaviour, and also a surprise for the author. |
| **Tenant provisioning.** Creating a tenant is an `INSERT` by the owner. Everything after it (principals, repositories) is written by `factory_app` with the setting made. There is no onboarding procedure, and no function that creates a tenant together with its first rows. | The API and admin work. | The owner sees no row of a tenant table under `FORCE`, so a script run as the owner cannot create them. |

## Not built, but named in the design

| Not covered | Note |
|---|---|
| **The external anchor** for the audit chain head and the hourly verification job (`policies/security.yaml`, `audit`). | The chains are tamper-evident only to someone who holds an earlier head. See [ledger-and-audit.md](ledger-and-audit.md). The hourly job must run per tenant, as a session set to that tenant, or as a dedicated role with a policy of its own. |
| **The Rust chain verifier**, with RFC 8785 canonical form and JSON Schema checks. | The database checks the hash and the columns, not the canonical form or the schema. |
| **`external_effect` table** for effects outside the database (ADR 0004). | Slice 2, with the consumers. |
| **A general command idempotency table** for repeated human or worker commands (state-machine ground rule 7). | Jobs have an idempotency key, deliveries a unique id, events a unique version, inbox rows a key. A repeated approve or cancel command is covered by the unique index on approvals and by the state machine, but there is no table of seen command keys. The engine package should say whether it needs one. |
| **Budgets, quotas and cost counters.** | The schema has `max_attempts` per stage run and nothing for tokens, spend, concurrency or job quotas. They live in the broker and the policy engine for now. |
| **Job tokens of the model broker.** | The broker stores its own hash, binding and counters (`secrets-and-credentials.md`, section 4.2). `api_tokens` is not that table. |
| **Stage contracts, gate reports, review verdicts, specifications and plans as tables.** | They are artifacts named by hash. The database stores the hash and the metadata. Their schemas are validated by the code that writes them. |
| **The named allowlist** that gives a person authority. | Deliberately absent. Policy says it is read from protected configuration and never from the database. |
| **Backups, point-in-time recovery, replication, connection pooling, TLS, encryption at rest, `pg_audit`.** | `sre` items. The suites test none of them. Since `s1-database-review`, a dump and restore round trip is checked on a scratch cluster (rows, catalog, triggers, policies, grants, chains and isolation through a real login survive; no planner statistics do): [operating-settings.md](operating-settings.md). Not tested: a replica, point-in-time recovery (there is none), the Docker drill. |

## Not proven by these tests

| Not covered | Note |
|---|---|
| **`diesel-async` running `set_config` as the first statement of a transaction.** | **Checked** by `s1-database-review`: the storage crate's `tenant_isolation` and `pool_reset` tests pass against a real server as the three real logins; see [adr-0012-open-items.md](adr-0012-open-items.md). | |
| **A transaction-mode connection pooler** (PgBouncer and the like). | None is planned for Slice 1 and none was run. The setting is transaction-local, which is what a transaction pooler needs, provided every statement runs inside a transaction that began with it. A session-level `SET` would leak between clients (shown in the suite). |
| **Behaviour under real load.** | **Measured on one laptop** (`s1-database-review`): [performance.md](performance.md) has the timing of every hot statement at 100,000 rows, concurrency up to 16 clients, ninety seconds of heartbeats, the autovacuum defaults and the bloat. `fillfactor` is at its default, and the review found no reason to change it. The cost of the extra `set_config` round trips per transaction is measured there (two statements, 20 to 40 microseconds on loopback). | Not measured: a network between the application and the database, production hardware, a database that has run for months. |
| **Isolation levels other than `READ COMMITTED`**, replicas and failover. | The audit chain's advisory lock reasoning for `REPEATABLE READ` is untested. |
| **PostgreSQL 17.** | 16.15 and 18.6 are the versions that ran. 17 was not run. |
| **A migration role that is neither a superuser nor the creator of the groups.** | Migration 14 refuses it with a message. Tried: a plain `CREATEROLE` owner that created the roles migrates, reverts and migrates again. One that did not create them stops. |
| **The Rust code.** | Compiled and tested since `s1-storage-postgres`. The tests that touch the database are the crate's own; this directory's SQL suites do not run Rust. | |
| **Upgrade from an earlier schema.** | The `migrations` suite upgrades from migration 14 with a row in every table; since `s1-database-review` the `compat` suite does it one migration at a time and runs the earlier code's statements after each, and `scripts/db-compat-rust.sh` runs the earlier release's real integration tests against each schema. Migrations 10 to 14 have no earlier code to run. See [migration-safety.md](migration-safety.md). | |
| **Tenant scoping in the Rust code.** | The tests prove the keys and the policies. They cannot prove that every repository call opens its transaction for the right tenant. |
| **`pg_stat_activity`, logs and error messages as side channels.** | Not examined. The tenant is sent as a bound parameter, not as a literal. The two global unique keys do name the key in an error (tested). |
| **Business rules above the schema.** | Transition guards, gate decisions, pipeline order (INV-06, INV-11), rework counts, who may do what. These are in the domain and the engine. |
| **Whether artifact bytes match their hash.** | The artifact store checks that on read. |

## Known weak points in what is covered

| Weak point | Detail |
|---|---|
| **The tenant setting is a convention, not a credential.** | Any SQL that a tenant login can run may call `set_config('factory.tenant_id', ...)` for another tenant (shown in the `rls` suite). Row-level security stops a forgotten `WHERE`, a cross-tenant logic bug and a stray query. It does not stop SQL injection that can run a second statement, or whoever holds the login's password. A stronger binding (one login per tenant, or a setting that only a `SECURITY DEFINER` function can make valid) was not designed. |
| **A pooled connection with a session-level `SET`** shows its tenant to the next borrower. | `Store` never makes one. The pool should `RESET factory.tenant_id` on return. Shown, and shown ended by `RESET` and by `DISCARD ALL`. |
| **The two global unique keys are existence oracles.** | `repositories.github_repository_id` and `api_tokens.token_hash` answer with `23505` naming the key, and `ON CONFLICT DO NOTHING` skips silently, for a value another tenant holds. Needed for the lookups before a tenant is known. The storage crate must return a closed error. |
| **`outbox.seq` is global.** | A tenant sees gaps where other tenants' events, and rolled-back ones, took numbers. It reveals the rate of other tenants' activity, not their content. |
| **The chain verifiers read under the caller's policy.** | `audit_verify_chain($other)` from a session for tenant 1 finds no row and answers NULL, "sound". The verification job must run per tenant. |
| **A disabled repository is indistinguishable from an unknown one at the lookup.** | By the ADR's "no reason" rule. An admission denial for a disabled repository is recorded under the platform tenant. |
| **The system scope is not narrower than `lease.sql` says it is.** | The reference SQL finds and the tenant transaction writes. If the engine author needs the system role to write (to claim in one transaction), that is a policy change, not a code change. |
| **Only stage runs and attempts are frozen once terminal.** | `state-machine.json` asks for it only for stage runs (INV-04). A terminal job or task node cannot change status, because no transition leaves a terminal state, but its other columns (for example `policy_hash`) can still be edited by the application role. Freezing them is a small trigger if the architect wants it. |
| **A superuser can rewrite everything.** | The chains show partial tampering. A consistent rewrite from some point forward passes both verifiers. A superuser also bypasses every policy. |
| **Deleting the end of the audit chain is not found** by `audit_verify_chain`. | A test states this limit. Only the anchor catches it. |
| **The owner role can `DROP TABLE`, and can turn row-level security off.** | Operational control only. `FORCE` stops an accident, not the owner. |
| **The application role can create temporary tables.** | `TEMPORARY` on a database goes to `PUBLIC` by default. The trigger functions and the two lookups qualify every table with `public.` and pin `search_path`, so a temporary table cannot shadow what they read (tried, with a control). Revoking `TEMPORARY` from `PUBLIC` and granting it back to the roles that need it is a hardening step for the deployment. |
| **Audit writes serialize per tenant.** | Fine at expected volume. If one job produced audit events at a high rate, the advisory lock would show up as latency. Writing audit events last in a transaction limits it. |
| **The composite keys, triggers and policies add write cost.** | Every ledger, outbox and audit insert checks several keys, `jobs` has two indexes that start with `(tenant_id, id)`, and `ledger_entries` has two that start with `(tenant_id, job_id, sequence)` (the planner picks either). Not measured under load. |
| **`UNIQUE (tenant_id, body_sha256)` on deliveries** rests on an assumption about GitHub payloads. | See [constraints-and-indexes.md](constraints-and-indexes.md). |
| **Fixed limits** (a one-hour lease bound, a 16 KiB outbox payload, 1 MiB request text, 20 attempts per run) are my sanity bounds. | The policy gives no figure. Change them by migration. |

## Added by `s1-database-port-alignment`

| Not covered | Note |
|---|---|
| **An upper bound on `not_before`.** A back-off or a postponement can park a run far in the future. | The policy gives no figure, so none was invented (the one-hour bound on a lease exists for a skewed worker clock; a back-off has no such risk). The engine's retry delay is bounded in the domain. |
| **Write-once job facts.** `policy_hash` and `normalized_request_sha256` can be changed by the tenant role. | The port says a changed fact is `Constraint(IdReusedWithDifferentContent)`. ADR 0010 re-runs `INTAKE` when the request changes, which may need a new normalized request, so a trigger was not added. The adapter checks. |
| **Who may raise `autonomy_ceiling`.** The tenant role can raise it. | Whether the caller is an organization admin is the API's authority check (policy), not a database role. `record_protection_preflight` does not touch it; it writes the preflight flag only. |
| **The platform tenant can be used like any tenant** by a tenant-pool session that sets its id. | As for every tenant, the setting is not a credential (point 1 above). The port gives the platform tenant one entry point and `cargo xtask` scans the callers (ST-13). |
| **A decision with no head can repeat** (pause, cancel). | `approvals_one_decision_per_head` needs `pr_head_sha`. A pause, a resume and a pause is legitimate. |
| **The approval invalidation reasons** are free text of 1 to 1,000 characters. | The port has five and the policy lists seven; the closed set belongs to whoever settles that difference. |
| **A task plan has one hash per stage run.** The database does not refuse nodes of two plans in one run. | The port's `insert_task_graph` is atomic and compares the plan hash first; the adapter locks the stage run to serialize two writers. A trigger that takes the same lock was left out as more machinery than the risk calls for. |
| **`artifacts.size_bytes` is required.** | A reference without a size cannot be indexed. The adapter takes the size from the blob it stored. |
| **Nothing was run in Rust, and `FOR SHARE` on the job in `start_attempt` was not measured under load.** | The lock is held for the length of one transaction of a few statements; the order job, run, attempt, task node is documented, and a deadlock is retried. |
