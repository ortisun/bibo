# Tenancy: keys and scoped queries now, row-level security later

- Status: decision for the Slice 0 baseline, with one open conflict that needs a person. The tests named below pass on PostgreSQL 18.6.
- Form: explanation.
- Source: [ADR 0007](../adr/0007-persistence-access-and-tenancy.md) rule 4, `policies/security.yaml` section `tenancy`, [threat model](../security/threat-model.md) T-28 and control C-36, negative tests NT-TEN-01 and NT-TEN-05.

## The question

The brief asked for a decision between two ways of keeping one tenant's rows away from another tenant:

- **Tenant-scoped keys and queries.** Every row carries `tenant_id`, foreign keys and unique keys include it, and every repository call takes a tenant scope.
- **Row-level security (RLS).** The database filters rows by a per-transaction setting, whatever the query says.

## The decision

This baseline uses **tenant-scoped keys and queries, and does not enable RLS.** That is what ADR 0007 rule 4 says: "Row-level security is **not** in Slice 1. The DBA proposes an ADR for it before Slice 4." I followed it, and I checked that the choice holds up on this schema.

### The conflict that needs a person

`policies/security.yaml` says `tenancy.database_row_level_security: required`, and control C-36 in the threat model lists row-level security. ADR 0007 is an accepted decision that defers it. The two documents disagree, and I do not own either of them. Until someone reconciles them, the baseline follows the ADR, and the negative test NT-TEN-01 (a session for tenant A reads tenant B's rows, "fails closed without a tenant") cannot pass because it assumes RLS. Its owner needs to either move it to the RLS work or accept the key-based tests below as its Slice 1 form.

The threat model's open question Q9 says isolation controls for several tenants are required before the second tenant. I recommend that RLS lands before then, and in any case before Slice 4.

## Why not RLS now

1. **The accepted ADR defers it.** A DBA can propose a change to an ADR. A DBA should not quietly override one.
2. **RLS does not fit three paths without a design for each.** The port sketch has two scopes: `TenantScope` and `SystemScope`. The claim, the sweeper and the outbox relay work across all tenants, so under RLS they need a role that bypasses it or a set of functions that run with the owner's rights. The API finds the tenant from the token hash, and the webhook receiver finds it from the repository binding. Both lookups happen before any tenant is known. Each of these is a decision with security consequences (a `BYPASSRLS` role is a powerful credential, and a `SECURITY DEFINER` function needs a pinned `search_path`). They deserve their own ADR, written with the storage engineer who has to implement them.
3. **Slice 1 runs one tenant.** The data model is tenant-aware from the start so that nothing needs rewriting later.

## What the baseline gives instead

All of this is tested in the [`tenancy`](tests/tenancy.sql) suite, which reads the structure from the catalog so that a new table cannot skip a rule.

| Property | How | Check |
|---|---|---|
| Every tenant-owned table has `tenant_id NOT NULL`, first in its primary key | Catalog scan of the 17 tenant-owned tables | `tenancy` |
| No table is silently untenanted | Every table is either tenant-owned or one of four known shared tables | `tenancy` |
| A child cannot point at another tenant's parent | All 31 foreign keys between tenant-owned tables join `tenant_id` to `tenant_id`; 14 of them are tried against a tenant 2 parent and refused with SQLSTATE 23503 | `tenancy` |
| A child cannot point at another job's row inside its own tenant | Children of a stage run also name the job; four cases tried | `tenancy` |
| Unique keys are per tenant | All 42 unique indexes include `tenant_id`, except the two documented in [constraints-and-indexes.md](constraints-and-indexes.md); the same delivery id, artifact hash and idempotency key are accepted in two tenants and refused inside one | `tenancy` |
| An event cannot name another tenant's aggregate | The polymorphic `aggregate_id` is checked at commit, with the tenant in the lookup | `outbox` |
| A lookup that forgets the tenant is not caught by slowness | PostgreSQL 18 can skip-scan the composite key, so the query is still an index scan. The mistake would be silent. | `plans` |

The last row matters. The hazard that RLS removes is a hand-written query that leaves out `AND tenant_id = $1`. Nothing in the database notices it, and it is not slow. What stops it in this design is the `TenantScope` argument on every repository method, which the type system enforces, together with the per-method isolation tests that ADR 0007 requires from the storage engineer. This is the deliberate gap the ADR names. The tests above prove that the keys hold. They cannot prove that the Rust code always passes the right tenant.

## RLS tried on this schema, then rolled back

The last section of the `tenancy` suite switches RLS on for `jobs` inside a transaction, runs checks, and rolls everything back. It shows the candidate design in the ADR (`FORCE ROW LEVEL SECURITY` with a per-transaction setting) works on this schema:

| Check | Result |
|---|---|
| A session with `factory.tenant_id` set to tenant 1 sees only tenant 1's jobs | passes |
| A query for a tenant 2 job by id returns nothing | passes |
| An `UPDATE` or `DELETE` of a tenant 2 job by id changes zero rows | passes |
| With no tenant set the policy returns zero rows (fails closed) | passes |
| A role with `BYPASSRLS` sees every tenant (the system scope) | passes |
| After the rollback RLS is off again and the test role is gone | passes |

It is a spike on one table, and it does not prove the whole design. It does show where the work is.

### What the RLS ADR should settle

1. **Setting the tenant.** `Store::begin(scope)` runs `SELECT set_config('factory.tenant_id', $1, true)` as the first statement of the transaction. The third argument makes it local to the transaction, so it survives a transaction-mode connection pool and cannot leak to the next borrower of the connection.
2. **The system scope.** Either a separate login role with `BYPASSRLS` used only by the engine, or policies that admit a setting that only that role may set. A separate role is simpler to audit.
3. **The lookups before the tenant is known.** Token authentication and webhook binding need `SECURITY DEFINER` functions or a narrow policy on `api_tokens` and `repositories`. Both must pin `search_path`.
4. **Foreign key checks.** The PostgreSQL documentation says referential integrity checks bypass row security. That would keep the composite keys working under RLS, but it was not tested here, and the spike covers one table only. The keys are not replaced by RLS and should stay.
5. **A test that discovers the tables.** NT-TEN-01 asks for every table with a tenant column to be discovered from the catalog. The structural test above shows how.

## The platform tenant

Audit events that belong to no tenant (a webhook with a bad signature, an unknown installation) are recorded under one fixed tenant, `00000000-0000-0000-0000-000000000001`, of kind `platform`. Every audit row then has a tenant and a chain. A partial unique index allows only one platform tenant. Nothing stops a job from being created under it. A person should confirm this choice, or say that such events belong somewhere else.
