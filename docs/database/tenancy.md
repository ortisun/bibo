# Tenancy: keys, scoped queries and row-level security

- Status: as built by the work package `s1-database-tenancy-and-state-sync`, on PostgreSQL 18.6. Implements [ADR 0012](../adr/0012-row-level-security-in-slice-1.md), which is pending human confirmation (item 13 of ADR 0009). Not yet reviewed by the software architect or the security specialist.
- Form: explanation, with a reference table of roles and a how-to for the storage author (the how-to proper is in [for-the-storage-crate.md](for-the-storage-crate.md)).
- Source: [ADR 0007](../adr/0007-persistence-access-and-tenancy.md) rule 4, ADR 0012, `policies/security.yaml` section `tenancy`, the [threat model](../security/threat-model.md) (T-28, control C-36) and negative tests NT-TEN-01 and NT-TEN-05.
- Proof: the `rls` and `tenancy` suites of `scripts/db-test.sh`. Every claim below names the check that shows it.

## In one paragraph

Two layers keep tenants apart, and each catches a fault the other misses. The **keys** (a `tenant_id` in every primary key, in every foreign key between tenant tables, and in almost every unique key) refuse a write that points at another tenant's row. **Row-level security** hides other tenants' rows from a session, so a query that forgets `WHERE tenant_id = $1` returns nothing instead of everything. A transaction for a tenant starts by telling the database which tenant it is for; a session that never says sees no rows and gets no error. Work that has to look across tenants (the claim, the sweep, the outbox relay) uses a different database role with its own, narrower policies. Two small functions answer the questions that come before any tenant is known.

## The roles

Four groups, none of which can log in. The deployment creates one or more **logins** as members of them.

| Group | Used for | What it can do | Who may be a member |
|---|---|---|---|
| `factory_app` | Everything done for one tenant | The grants in [privileges](tests/privileges.sql), filtered to one tenant by the policies below | The API login and the tenant pool of the worker login |
| `factory_system` | The engine's cross-tenant loops: claim, sweep, relay | Read the columns those queries need on `stage_runs`, `jobs`, `attempts`; lock `stage_runs` and `attempts`; read the outbox and mark events published. No insert, no delete, no status change. See [the system scope](#the-system-scope) | One login, used by `Store::begin_system` in the `workflow` crate |
| `factory_resolver` | The two lookups before a tenant is known | Execute `resolve_token` and `resolve_installation`. No table access | The API login only |
| `factory_lookup` | Owns the two lookup functions | Read the columns they use, through policies of its own | Nobody. The migration role holds it for a moment to hand the functions over |

What the suite checks about the roles (`rls`, section 1, and the shell part):

- None has `SUPERUSER`, `BYPASSRLS`, `CREATEROLE`, `CREATEDB`, `REPLICATION` or `LOGIN`. None owns a table, a view, a sequence or a schema. None can create objects in `public`.
- **No login is a member of both `factory_app` and `factory_system`.** Permissive policies are combined with OR, so a login in both would see every row. The suite builds such a login and shows it reads every tenant's jobs, then shows that the membership check reports it. The same rule keeps `factory_system` apart from `factory_resolver`, and `factory_lookup` free of members.
- The API login is the one login that belongs to two groups (`factory_app` and `factory_resolver`). That pair is allowed.
- A membership that carries only the ADMIN option, which the role that created a group gets on PostgreSQL 16 and later, is not counted as a member: it confers neither the privileges nor the right to switch to the role.

```sql
-- What a deployment creates. Passwords come from the secret store; none is written in the repository.
CREATE ROLE factory_api    LOGIN PASSWORD '...' IN ROLE factory_app, factory_resolver;
CREATE ROLE factory_worker LOGIN PASSWORD '...' IN ROLE factory_app;
CREATE ROLE factory_engine LOGIN PASSWORD '...' IN ROLE factory_system;
```

## The policy on each tenant table

Seventeen tables carry a `tenant_id` column, found from the catalog (`dbtest.tenant_tables()` in the suite). Each has `ENABLE` and `FORCE ROW LEVEL SECURITY` and one policy:

```sql
CREATE POLICY tenant_isolation ON <table> AS PERMISSIVE FOR ALL TO factory_app
  USING      (tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid);
```

- **`NULLIF` is required.** On a connection that has finished a transaction which made the setting, the next transaction reads the setting as an **empty string, not NULL** (checked: `current_setting(...) IS NULL` is false). Without `NULLIF`, `''::uuid` raises `invalid input syntax for type uuid` and the failure depends on what ran before on that connection. The probe, on the real `jobs` table with the `NULLIF` taken out: the first transaction returns 1 row, the second transaction on the same connection fails with `ERROR: invalid input syntax for type uuid: ""`. With the policy as built it returns 0 rows and no error.
- **A value that is not a uuid still fails loudly** (22P02). A bug in the caller is not quietly empty.
- **`FORCE` binds the table owner.** The policy names `factory_app` only, so the owner sees no row and can write none (measured with an owner that is not a superuser: 2 rows without `FORCE`, 0 with it). A superuser bypasses everything, whatever is set.
- **`tenants`** has no `tenant_id`. It has `ENABLE` without `FORCE`, and `tenant_self`: a tenant session reads its own row only. It is not forced because onboarding a tenant is an `INSERT` by the owner, and the owner has no policy to work under. The application role has `SELECT` on it and nothing else.
- **Four reference tables** (the three state machine tables and the Diesel version table) hold no tenant data and have no policy. `factory_app` can read them.
- **The suite closes the list.** The set of policies in the database must equal a list written in the suite (`expected_policies`): 29 policies today. An extra policy, a missing one, a policy for `PUBLIC` or a restrictive one fails it.

What a tenant-1 session gets, from the `rls` suite (all 17 tables, each attempt in a subtransaction that is rolled back, with a control that shows the attempt would have worked for tenant 2):

| Attempt by tenant 1 | Result |
|---|---|
| `SELECT` of every row | Its own rows only |
| `SELECT` asking for tenant 2's rows | Zero rows |
| `INSERT` of an exact copy of a tenant 2 row | `42501 new row violates row-level security policy` (tenant 2 itself gets the primary key error, so the policy is what stopped tenant 1) |
| `UPDATE` of tenant 2's rows, with a temporary column grant | Zero rows |
| `UPDATE ... SET tenant_id = <tenant 2>` on its own row | `42501` (the check refuses the new row) |
| `DELETE` of tenant 2's rows, with a temporary grant | Zero rows |
| The same with the setting empty | Zero rows for read, update and delete; `42501` for insert |
| The setting `not-a-uuid` | `22P02`, no rows |

The temporary grants matter: the application role has no `DELETE` and almost no `UPDATE` today, so without them the test would be answered by the missing privilege. With them, the policy alone has to answer, and it does. A future grant of `DELETE` to `factory_app` is covered before anyone makes it.

## Making the setting, and what a pooled connection does

`Store::begin(scope)` runs `SELECT set_config('factory.tenant_id', $1, true)` as the first statement of the transaction, with the tenant as a typed parameter. The `true` makes it local to the transaction.

Checked with real logins (`rls`, shell part), each as a separate session:

| Case | Result |
|---|---|
| A session that never made the setting | Zero rows, no error; the setting is NULL |
| A second transaction on a reused connection | Zero rows, no error; the setting reads as an empty string |
| `RESET factory.tenant_id` inside a transaction | Zero rows, no error |
| A savepoint that changes the setting and is rolled back | The outer transaction's tenant is back |
| `set_config` with the tenant as a **bound parameter** of the extended protocol (`\bind`, the way a Rust driver sends it) | Works as the first statement of a transaction |
| A prepared statement with a generic plan, run for tenant 1, then tenant 2, then no tenant, on one connection | Each gets its own rows. The policy reads the setting when the statement runs, not when it is planned |
| `SET row_security = off` | The query fails (`query would be affected by row-level security policy`); it does not return all rows |
| `SET ROLE factory_system`, `SET SESSION AUTHORIZATION`, `ALTER TABLE ... DISABLE ROW LEVEL SECURITY`, `DROP POLICY`, `CREATE POLICY` by a tenant login | Refused |
| `COPY <tenant table> FROM STDIN` | Refused (`COPY FROM not supported with row-level security`). Bulk loads must use `INSERT`. `COPY ... TO` returns the session's tenant only |

**What it does not protect against.** The setting is a convention that the `Store` enforces. It is not a credential: any SQL that a tenant login can run may call `set_config('factory.tenant_id', <another tenant>, true)`, and the suite shows it (`KNOWN LIMIT`). Row-level security here stops a forgotten `WHERE`, a cross-tenant logic bug and a stray query. It does not stop SQL injection that can run a second statement, or someone who holds the login's password. The defences against that sit above the database: the `Tx` type has no method that runs raw SQL or changes the setting, queries use bound parameters, and the logins' passwords are secrets. The same applies to a **session-level** `SET` on a pooled connection, which survives the transaction and shows its tenant to the next borrower (`KNOWN LIMIT`, also shown). `Store` never makes one, and the pool should `RESET factory.tenant_id` (or `DISCARD ALL`) when it takes a connection back.

## The system scope

The claim, the sweep and the outbox relay find work across tenants. They use `factory_system` through their own login and pool. A system transaction **finds work and returns identifiers**. The change itself (the compare and swap on the stage run, the attempt, the ledger entry, the event) is made in a tenant transaction for the tenant that was found, so it happens under the tenant policy.

| Table | Columns it can read | Writes | Policies |
|---|---|---|---|
| `stage_runs` | `tenant_id, id, job_id, status, version, not_before` | None. Can lock (`FOR NO KEY UPDATE`) | `system_find` (select, all rows); `system_lock` (update, `USING true WITH CHECK false`) |
| `jobs` | `tenant_id, id, status` | None | `system_find` |
| `attempts` | `tenant_id, id, job_id, stage_run_id, status, version, lease_epoch, lease_expires_at, deadline_at, teardown_deadline_at` | None. Can lock | `system_find`, `system_lock` |
| `outbox` | All columns (the relay publishes whole events) | `published_at`, `publish_attempts` | `system_find`, `system_relay` (update, `USING true WITH CHECK true`) |
| `__diesel_schema_migrations` | `SELECT`, for the start-up check | None | none (reference table) |

Everything else is refused to it, and the suite lists the refusals: the ledger, the audit log, tokens, approvals, requests and the other ten tables give `permission denied`; so do `tenants`, a whole-row `SELECT *` on the three tables it uses, and every insert, update of a status, delete and truncate.

**Why it can lock but not write.** `SELECT ... FOR NO KEY UPDATE SKIP LOCKED` needs an `UPDATE` privilege on one column of the table and an `UPDATE` policy that lets the lock see the row. The column is `updated_at`, the policy says `WITH CHECK (false)`, and the `bump_guard` trigger refuses an update that does not raise the version. Three layers; the suite shows the trigger answering with the triggers on and the policy answering with them off.

**Two claimers can find the same run.** The lock of a system transaction ends when the transaction ends, which is before the tenant transaction starts (holding it would deadlock the second connection). The compare and swap on `version` and the unique index of one live attempt per stage run decide the winner. The shell race runs 12 rounds of four workers through two logins; in 7 and 8 of the 12 rounds of the two runs made, more than one worker had found the same candidate, and every round ended with exactly one winner and one live attempt.

**The lock mode.** The `lease` suite still shows that a ledger append by the tenant role is not blocked while the system role holds the stage run `FOR NO KEY UPDATE`, and is blocked (lock timeout) while it holds it `FOR UPDATE`. The sweep uses `FOR NO KEY UPDATE` too: the plans suite used `FOR UPDATE` on `attempts` before, and a ledger entry points at an attempt.

A new loop later (a timer for paused jobs, say) is a new migration with its own policy and a new line in the `rls` suite. This list is complete for Slice 1.

## The two lookups before a tenant is known

| Function | Takes | Returns | Misses |
|---|---|---|---|
| `resolve_token(p_token_hash bytea, p_audience text)` | The SHA-256 of the presented token and the audience the API serves | `(tenant_id, principal_id)` | Zero rows for: never stored, wrong audience, expired, revoked, owner disabled, tenant disabled |
| `resolve_installation(p_installation_id bigint, p_github_repository_id bigint)` | The GitHub installation id and repository id of a webhook | `(tenant_id, repository_id)` | Zero rows for: not registered, the pair does not belong together, repository disabled, tenant disabled |

How they are made safe, each point checked in `rls` section 5 and the `tokens` suite:

- **SECURITY DEFINER, owned by `factory_lookup`**, a role bound by row-level security like any other. It has `SELECT` on the columns the functions read (`tenants.id, disabled_at`; `principals.tenant_id, id, disabled_at`; `api_tokens` without `label`, `created_at` and `last_used_at`; `repositories.tenant_id, id, github_installation_id, github_repository_id, enabled`) and a read policy `lookup_read` on those four tables. It cannot write, and cannot read `principals.login` or `repositories.full_name`.
- **`search_path` pinned** to `pg_catalog, pg_temp`, and every table qualified with `public.`. A test creates a temporary table named like the real one, puts it first on the path and calls the function: no redirect. A control builds the same function without the qualification or the pin and shows the redirect works there, so the test can fail.
- **`PUBLIC` has no `EXECUTE`.** Only `factory_resolver` (and the owner) can run them. The tenant role and the system role cannot, so a compromised worker cannot test token hashes or ask which tenant holds an installation.
- **They return identifiers and nothing else**, from a catalog check of the result type.
- **The table owner would be the wrong owner.** A definer function owned by the table owner is bound by `FORCE` and counts zero rows (checked). An owner role with its own policy is not.

Two differences from the text of ADR 0012, for the architect:

1. `resolve_installation` takes the GitHub **repository** id as well. One installation covers many repositories, so the installation alone does not name one; the pair does, because `repositories.github_repository_id` is unique across tenants. The sketch in section 7 of the slice plan has `resolve_installation(installation)`.
2. The lookups read **four** tables, not two. The view `active_api_tokens` joins `principals` (a disabled owner) and, since the migration `rls_lookup_functions`, `tenants` (a disabled tenant). Before it nothing read `tenants.disabled_at`, so a disabled tenant's tokens still authenticated.

Consequence for the receiver: a disabled or unregistered repository gives no row and no reason, so an admission denial for a disabled repository cannot be attributed to its tenant by the lookup. The receiver records it under the platform tenant like an unknown installation. If the architect wants the tenant for audit, the function could return `enabled`; that would be a reason, which the ADR forbids.

## Foreign key checks and row security (a "not verified" item of ADR 0012)

**They bypass it, on this schema, including under `FORCE ROW LEVEL SECURITY`.** Checked in the `tenancy` suite, section 4, as a tenant-1 session:

1. A temporary restrictive policy hides every stage run from the session (`SELECT` returns 0 rows). The session still inserts a `stage_run_artifacts` row pointing at a stage run it cannot see. The referential check does not apply policies.
2. A restrictive policy hides the child rows. Deleting the parent still fails with `23503`, because the check sees the child.
3. The composite keys still refuse another tenant's parent: 14 cases in section 2 are run as a tenant-1 session with row-level security on, each reaching `23503` (the policy lets the row in because its `tenant_id` is tenant 1's, and the key refuses it).
4. **Unique keys are checked against every row too.** The two global keys (`repositories_github_repository_id_key`, `api_tokens_token_hash_key`) answer a tenant that tries a value another tenant holds with `23505` naming the key, while the same session cannot read that row. Existence is an oracle on those two keys. The storage crate must return a closed error and never the database message (already in the storage notes).

So the keys stay, as ADR 0012 says: they catch a wrong tenant on a write, which the policy (it sees one row, not its parent) does not.

## Other things an attacker tries

| Attempt | What happens | Where checked |
|---|---|---|
| Read through a view | Every view in the schema has `security_invoker`, so the policy of the caller applies. A catalog check fails the suite on a view without it | `rls` section 5 |
| Use a trigger function to read another tenant | Trigger functions run as the caller and pin their path. The suite requires a pinned path on every function in `public` | `rls` section 5 |
| Call `ledger_verify_chain` or `audit_verify_chain` for another tenant | They read under the caller's policy: zero rows, and the audit verifier answers NULL, "sound". **A verifier must run for the right tenant** (known limit, below) | `rls` section 7 |
| Learn another tenant's activity from `outbox.seq` | The sequence is global, so a tenant sees gaps (known limit) | `rls` section 7 |
| Truncate to get around the policy | `TRUNCATE` ignores policies, and no application role has it | `privileges` |
| Own the tables and turn it off | No application role owns a table; `ALTER TABLE ... DISABLE ROW LEVEL SECURITY` is refused | `rls`, shell part |
| Become the system scope | `SET ROLE factory_system` is refused for tenant logins; a login in both groups is a finding | `rls` |
| Poison a pooled connection with a session-level `SET` | Works if the pool lets it; `RESET`/`DISCARD ALL` ends it (known limit) | `rls`, shell part |
| Bypass with a superuser or `BYPASSRLS` role | By nature. No role of the design has either; the suite checks the groups and their members | `rls` |

## Known limits, short

1. The tenant setting is a convention, not a credential (above).
2. A session-level `SET` survives on a pooled connection.
3. The two global unique keys are existence oracles.
4. `outbox.seq` is global, so a tenant sees gaps.
5. Chain verifiers read under the caller's policy: run `audit_verify_chain($tenant)` and `ledger_verify_chain($tenant, $job)` in a transaction for that tenant, and treat a NULL from a session set to another tenant as no answer.
6. `COPY FROM` into a tenant table is not available.
7. The owner sees no tenant row (with `FORCE`). A migration that backfills tenant data must lift `FORCE` on that table for its own duration (see [migration-safety.md](migration-safety.md)).
8. A disabled repository is indistinguishable from an unknown one at the lookup.

## What the keys and scoped queries still give

All of this is tested in the [`tenancy`](tests/tenancy.sql) suite, which reads the structure from the catalog so that a new table cannot skip a rule.

| Property | How | Check |
|---|---|---|
| Every tenant-owned table has `tenant_id NOT NULL`, first in its primary key | Catalog scan of the 17 tenant-owned tables | `tenancy` |
| No table is silently untenanted | Every table is tenant-owned or one of four known shared tables | `tenancy` |
| A child cannot point at another tenant's parent | All 31 foreign keys between tenant-owned tables join `tenant_id` to `tenant_id`; 14 are tried against a tenant 2 parent, as a tenant-1 session with row-level security on, and refused with `23503` | `tenancy` |
| A child cannot point at another job's row inside its own tenant | Children of a stage run also name the job; four cases tried | `tenancy` |
| Unique keys are per tenant | All 42 unique indexes include `tenant_id`, except the two documented in [constraints-and-indexes.md](constraints-and-indexes.md) | `tenancy` |
| An event cannot name another tenant's aggregate | The polymorphic `aggregate_id` is checked at commit, with the tenant in the lookup | `outbox` |
| A query that forgets the tenant | Without row-level security the lookup was still an index scan on PostgreSQL 18 (skip scan), so nothing looked wrong. With the policy it returns only the session's tenant: tenant 3 finds its job by id alone, tenant 1 gets zero rows | `plans` |

The `TenantScope` argument on every repository method and the per-method isolation tests of ADR 0007 stay. The tests prove the keys and the policies. They cannot prove that the Rust code opens the transaction for the right tenant.

## The platform tenant

Audit events that belong to no tenant (a webhook with a bad signature, an unknown installation, a disabled repository) are recorded under one fixed tenant, `00000000-0000-0000-0000-000000000001`, of kind `platform`. Every audit row then has a tenant and a chain. A partial unique index allows one platform tenant.

Under row-level security this has a consequence for the storage crate: writing such an event needs **a tenant transaction for the platform tenant**, since the audit table accepts nothing else. `TenantScope` is "built only from an authenticated principal" in the port sketch, and a rejected webhook has no principal. The ports need a constructor for the platform scope that only the receiver can reach. The `audit` suite does it with the setting `00000000-0000-0000-0000-000000000001`.

Nothing stops a job from being created under the platform tenant. A person should confirm this choice, or say that such events belong somewhere else.

## Decisions that need a person

1. **ADR 0012 itself**, still pending (ADR 0009 item 13).
2. **The system scope finds and does not write.** ADR 0012 section 3 says both that the policies cover "the statements in `lease.sql` and `outbox.sql`" (which update) and that "a system transaction only finds work and returns identifiers". This build takes the second sentence: the system role has no write on `stage_runs`, `jobs` or `attempts`. The cost is one more round trip per claim. The looser reading is one migration away.
3. **`resolve_installation` takes the repository id** (above), and the port sketch must follow.
4. **`active_api_tokens` and the lookups now refuse a disabled tenant.**
5. **`tenants` has a policy** (a tenant reads its own row), which the ADR does not mention. It is not forced, so onboarding stays an owner action.
6. **A platform scope for `TenantScope`** (above).
