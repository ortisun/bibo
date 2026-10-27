# 0012: Turn on row-level security in Slice 1, with a tenant setting in every transaction, a separate role for the system scope and two narrow lookup functions

- Status: Accepted by the architect. The default is **pending human confirmation** and is item 13 of [ADR 0009](0009-operating-defaults-pending-confirmation.md). It replaces four statements of [ADR 0007](0007-persistence-access-and-tenancy.md), which carries a revision note.
- Date: 2026-10-27
- Deciders: software_architect. The schema, the policies and the roles belong to the DBA, who implements them in the work package `s1-database-tenancy-and-state-sync`.
- Related: [ADR 0007](0007-persistence-access-and-tenancy.md), [tenancy](../database/tenancy.md), [notes for the storage crate](../database/for-the-storage-crate.md), `policies/security.yaml` section `tenancy`, [threat model](../security/threat-model.md) control C-36, negative tests NT-TEN-01 and NT-TEN-05

## Context and problem statement

`policies/security.yaml` says `tenancy.database_row_level_security: required`, and control C-36 of the threat model lists it. ADR 0007 said row-level security (RLS) was not in Slice 1 and that the DBA would propose a design before Slice 4. The negative test NT-TEN-01 asks that a session for tenant A cannot read, change or add tenant B's rows and that a session with no tenant sees nothing. Without RLS it cannot pass.

The `storage` crate does not exist yet. That is the cheap moment. Adding RLS after the repository methods are written means touching every query, every connection pool and every test fixture, and the first version of the code would be written against rules that change.

The DBA tried RLS on the `jobs` table inside a rolled-back transaction and listed what a design must settle (`docs/database/tenancy.md`). This record settles it.

## What was checked

On 2026-10-27.

- **The DBA's spike.** Six checks on `jobs` pass in the `tenancy` suite on PostgreSQL 18.6: a tenant sees only its rows, a lookup of another tenant's job by id returns nothing, an update or delete changes zero rows, no tenant setting gives zero rows, a `BYPASSRLS` role sees all, and the rollback leaves no trace.
- **A probe run by the architect** on a private PostgreSQL 18.6 cluster (Homebrew, aarch64), with a table, a `NOLOGIN` group role, a login role in it, and `FORCE ROW LEVEL SECURITY`.
  - With the setting never made, the policy shows zero rows and raises no error.
  - After a transaction that made the setting with `set_config('factory.tenant_id', ..., true)` has ended, the next transaction on the same connection reads the setting as an empty string. It is not NULL (`is_null` was false).
  - A policy written as `tenant_id = current_setting('factory.tenant_id', true)::uuid` then fails that next query with `invalid input syntax for type uuid: ""`. A policy written with `NULLIF(current_setting('factory.tenant_id', true), '')::uuid` gives zero rows and no error.
  - An insert for another tenant, while the setting names tenant A, fails with `new row violates row-level security policy`.
- **The lock claim.** `scripts/db-test.sh lease` passed on PostgreSQL 18.6 with 40 checks, including `lock modes: a ledger append is not blocked while a claimer holds the stage run FOR NO KEY UPDATE` and `the same append IS blocked while the stage run is held FOR UPDATE (lock timeout)`.
- **The catalog.** NT-TEN-01 is a P1 test in the negative test catalog, not P0. It is required before Slice 2, and this record moves its first pass into Slice 1.

Not verified: that foreign key checks still work under RLS on this schema (the PostgreSQL documentation says integrity checks bypass row security, which the DBA must test with the composite keys); how `SECURITY DEFINER` functions behave for a role that `FORCE ROW LEVEL SECURITY` also binds; the query plans with RLS on 10,000 and 100,000 rows; `diesel-async` running `set_config` as the first statement of a transaction; a transaction-mode connection pooler (none is planned for Slice 1).

## Considered options

1. **Keep ADR 0007 as accepted: no RLS until Slice 4.** One tenant in Slice 1, so no data is at risk yet. But the policy file says "required", the test cannot pass, and the retrofit costs more later.
2. **RLS in Slice 1 with a role per scope.** The tenant setting is made in each transaction. The engine's cross-tenant work uses its own role and pool. Two narrow functions serve the lookups that happen before a tenant is known.
3. **A schema or a database per tenant.** Stronger isolation, with migrations, pooling and operations multiplied by the tenant count. Far more than one tenant in Slice 1 justifies.

For the cross-tenant work (claim, sweep, outbox relay), three ways were weighed inside option 2.

| Way | Verdict |
|---|---|
| A role with `BYPASSRLS` | Rejected. The attribute skips every policy, including future ones, and a leak of its password is a leak of every tenant. |
| A policy that admits a second setting such as `factory.system = 'on'` | Rejected. Any session can set any setting, so it protects nothing. |
| A second group role with its own all-rows policies, its own login and its own pool | Chosen. The policies list exactly the tables and commands the engine loops need, and the database, not the application, decides who may use them. |

## Decision outcome

Chosen: **option 2.**

### 1. The policy on each table

Every tenant-owned table (found from the catalog, 17 today) gets `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`, so the table owner is bound too. One policy for the group role `factory_app` covers all commands and has the same condition for `USING` and `WITH CHECK`:

```sql
tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid
```

The `NULLIF` is required, for the reason the probe shows. A policy without it turns a forgotten setting on a reused connection into an error that depends on what ran before, instead of an empty result.

### 2. Setting the tenant

`Store::begin(scope)` runs `SELECT set_config('factory.tenant_id', $1, true)` as the first statement of the transaction, with the tenant from the `TenantScope` as a typed parameter. The third argument makes the setting local to the transaction, so it ends at commit or rollback and cannot reach the next borrower of the connection. Nothing else sets it. The `Tx` that `begin` returns has no method that runs raw SQL or changes the setting, and no `Store` method runs a statement outside a `Tx`. A repository method still puts `tenant_id` in its `WHERE` clauses and joins, because the keys and the isolation tests of ADR 0007 stay.

### 3. The system scope

A second group role, `factory_system`, has its own login and its own connection pool. It has all-rows policies (`TO factory_system USING (true) WITH CHECK (true)`) on the tables and for the commands that the claim, the sweep and the outbox relay use, which are the statements in `docs/database/tests/lease.sql` and `outbox.sql`, and on nothing else. `Store::begin_system` uses that pool. Because only the `workflow` crate may call it (rule DEP-09), the pool is reachable from one crate.

A system transaction only finds work and returns identifiers. When the engine applies the transition it opens a tenant transaction for the tenant it found, so every write to a job, a stage run, the ledger and the outbox happens under the tenant policy.

No application role has `BYPASSRLS`, owns a table, or is a superuser. No login role is a member of both groups, because permissive policies are combined with OR and the login would see every row.

### 4. Lookups before the tenant is known

Authenticating an API token and binding a webhook to a repository happen before any tenant is known. They use two `SECURITY DEFINER` functions, one for each, instead of a policy that admits everything on `api_tokens` and `repositories`.

- The functions return only identifiers: the tenant and the principal for a token hash and an audience, the tenant and the repository for an installation. A miss for any reason (unknown, expired, revoked, wrong audience, disabled owner) gives zero rows and no reason.
- They are owned by a `NOLOGIN` role, `factory_lookup`, that has a read-only all-rows policy on exactly those two tables (through the existing view for tokens). They set `search_path` and qualify every name, and `PUBLIC` has no `EXECUTE`. Only the API login can run them.
- The port gains two methods on `Store`, outside `Tx`: `resolve_token(hash, audience)` and `resolve_installation(id)`. The sketch in section 7 of the slice plan shows them. The ports are not tagged yet, so this changes no tagged contract.

### 5. What stays

The composite foreign keys that include `tenant_id`, the per-tenant unique indexes, and the `TenantScope` type stay. RLS removes the hazard of a forgotten `WHERE tenant_id`. The keys remove the hazard of a wrong tenant on a write. They are different faults and each layer catches what the other misses.

### 6. Tests and a check at start-up

- A new `rls` database suite finds every table with a tenant column from the catalog, as NT-TEN-01 asks, so a new table without a policy fails the suite. For each table it tries SELECT, INSERT, UPDATE and DELETE against another tenant's rows and with no setting, and a second transaction on a reused connection with no setting. It checks that no application role can bypass RLS, own a table or is a superuser, and that no login belongs to both groups.
- The suite has a control-off check, as catalog principle 2 requires: switching RLS off on one table makes it fail.
- The `plans` suite is re-run with RLS on, and the claim and sweep plans must still use their indexes.
- The `storage` crate's isolation tests run as the application login, never as the owner or a superuser, because those silently bypass the policies. At start-up the store reads its own role from `pg_roles` and refuses to become ready if it can bypass RLS or owns the tables.

### 7. When

Before `s1-storage-postgres` begins. The DBA package is a dependency of it.

### Amendments to ADR 0007

These are made in that record, with a revision note.

- Rule 4's statement that RLS is not in Slice 1 is replaced by a pointer to this record.
- Rule 6 now says that claiming work uses `FOR NO KEY UPDATE SKIP LOCKED`. `FOR UPDATE` conflicts with the `KEY SHARE` lock that a ledger, audit or outbox insert takes on the rows it points at, so a claimer would block the writers of evidence. `FOR NO KEY UPDATE` gives the same exclusion between claimers and does not. Measured on PostgreSQL 18.6 (above).
- The consequence "no row-level security until Slice 4" is removed.
- PostgreSQL 18 is the pinned major version in Compose, in CI and in the documents. The DBA already tested 18.6 and 16.15, and 17 was not run. The local Compose file still pins 17 (`infra/compose/postgres.yml`, read 2026-10-27), so the package `s1-ci-database-and-generated-checks` moves it to 18 and owns the data directory change of the 18 image.

## Consequences

- Good: the policy file, the threat model and the test catalog agree with the design. A hand-written query that forgets `tenant_id` returns nothing instead of another tenant's rows.
- Good: the system scope is a database fact. Code cannot widen it.
- Bad: two roles, two pools in the worker and a login restriction to maintain. The `rls` suite checks the restriction.
- Bad: every tenant transaction makes one more statement. The cost is one round trip and is measured in `s1-database-review`.
- Bad: a table owner or superuser run of a fixture bypasses the policies, so a test that does not connect as the application login proves nothing. The rule in section 6 exists for this.
- Neutral: Slice 1 has one tenant, so RLS is first exercised by tests with two.

## Revisit triggers

Write a superseding record if the integrity-check behavior or the `SECURITY DEFINER` interplay turns out to need a different design, if the plans show an index no longer used, or if a transaction-mode pooler is added.

## Confirmation

`scripts/db-test.sh rls plans`, `cargo nextest run -p factory-storage --test tenant_isolation`, and NT-TEN-01 and NT-TEN-05 passing. The DBA records which of the not-verified items were checked.
