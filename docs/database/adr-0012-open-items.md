# ADR 0012: the items it listed as not verified, and what was found

- Status: checked 2026-10-28 by the work package `s1-database-review`, PostgreSQL 18.6 (Homebrew), one laptop. ADR 0012 itself is still pending a human confirmation (item 13 of ADR 0009); this page does not change it.
- Form: reference. One section per item of the paragraph "Not verified" in ADR 0012, then the two costs the ADR named for this package.
- Where each result came from is named, with the command to repeat it.

## 1. Do foreign key checks still work under row-level security on this schema?

**Yes, and they bypass the policies, as the PostgreSQL documentation says.** `scripts/db-test.sh tenancy rls` passed (193 checks together). The relevant lines:

- `tenancy`: a foreign key into another tenant's row is rejected, also for a session under row-level security. The composite keys carry the tenant, so the rejection does not depend on the policy.
- `rls`: "a child row that points at a stage run the session cannot see is still accepted: the foreign key check bypasses row security." That is a fact to know, not a defect. The check sees the whole parent table; it is the composite key `(tenant_id, ...)` that stops a child from naming another tenant's parent, which is why ADR 0012 keeps the keys (decision 5).

Not covered: a foreign key *into a partitioned table* under row-level security (it works, `proto | D3`, [retention-and-partitioning.md](retention-and-partitioning.md)).

## 2. How do `SECURITY DEFINER` functions behave for a role that `FORCE ROW LEVEL SECURITY` also binds?

**They are bound by it, so the owner of a lookup function must be a role with a read policy of its own.** From the `rls` suite:

- `resolve_token` and `resolve_installation` are `SECURITY DEFINER`, `STABLE`, owned by `factory_lookup`, with the search path pinned to `pg_catalog, pg_temp`; they are the only `SECURITY DEFINER` functions in the product schema.
- "A `SECURITY DEFINER` function owned by that table owner is bound by `FORCE` too: it counts zero rows, so it is the wrong owner for a lookup." And "a `SECURITY DEFINER` function owned by another role with a read policy of its own counts every row: the owner the lookups have." This is why `factory_lookup` exists and holds `lookup_read` policies on `tenants`, `principals`, `repositories` and `api_tokens` (through the view).
- The harness times both lookups as the real API login: p50 0.11 and 0.09 ms, p95 0.21 and 0.12 ms at 100,000 rows ([performance.md](performance.md)).

## 3. What are the query plans with row-level security on, at 10,000 and 100,000 rows?

**Index scans everywhere on the large tables; the policy is cheap.**

- `scripts/db-test.sh plans` and `scripts/db-test.sh plans --rows 100000` both pass, 43 checks each. The plans are in [query-plans.md](query-plans.md). One plan changed in this package, the expired-lease sweep (migration 19).
- What the policy becomes in a plan, from the harness (`policy_probe` in the report):
  - A query that names the tenant gets a **one-time filter** that compares the setting with the tenant in the query: `One-Time Filter: ((NULLIF(current_setting('factory.tenant_id'::text, true), ''::text))::uuid = '<tenant>'::uuid)`, evaluated once, before the scan. `current_setting` is not evaluated per row.
  - A query that forgets the tenant gets the policy **as an index condition** on the leading column of the same index: `Index Cond: ((tenant_id = (NULLIF(current_setting(...), ''))::uuid) AND (id = '<job>'::uuid))`. It is still an index scan (3 buffers), and it returns only the session's tenant. The expression is index-friendly: the planner treats `current_setting` as a stable value fixed for the scan.
  - A session with **no** tenant setting gets an index scan that stops at once (`Index Searches: 0`) and returns nothing.
  - The system role's policies are `USING (true)`, and PostgreSQL drops them from the plan: the claim plan as `factory_system` has no policy filter.
- **The price of the policy**, by running the same 28 tenant series with the policies disabled (`ALTER TABLE ... DISABLE ROW LEVEL SECURITY` by the superuser, then enabled again and re-proved): the median statement takes **0.049 ms with the policies and 0.046 ms without**. The median of the per-series differences is **2 microseconds**, the largest 7, on statements that take 30 to 200. The cost is below what the harness can resolve from run to run. (28 series, 1,000 iterations each; the table is in [performance.md](performance.md).)

## 4. Does `diesel-async` run `set_config` as the first statement of a transaction?

**Yes.** `crates/storage/src/pg/tx.rs` (`start`) sends `BEGIN`, then `SELECT set_config('factory.tenant_id', $1, true)` with the tenant as a bound parameter, then the limits, in that order. `cargo test -p factory-storage` passes against a real PostgreSQL 18.6 as the three real logins (15 unit tests and 48 integration tests, 2026-10-28), among them:

- `tenant_isolation` (7): `negative_nt_ten_01`, `every_method_refuses_another_tenants_rows`, `a_reused_connection_carries_no_tenant_into_the_next_transaction`, `the_system_login_cannot_write_a_tenant_row`, `refuses_a_role_that_bypasses_rls`.
- `pool_reset` (1): `a_pool_without_the_reset_would_leak_the_tenant`, the deliberate break that shows why the pool runs `RESET factory.tenant_id`.

The harness sends the same statements over the extended protocol with named prepared statements, and the report's `generic_plan_index_only` field lists, for each single-statement series, the indexes a **generic** plan uses (the plan a prepared statement settles on after five executions), to show the policy does not change it.

## 5. Does it work behind a transaction-mode connection pooler?

**Not verified.** None is planned for Slice 1 and none is installed on the machine. By construction the setting is transaction-local (`set_config(..., true)`), which is what transaction pooling needs, provided every statement runs inside a transaction that began with it; the three lookups (`resolve_token`, `resolve_installation`, `schema_version`) do not, and would need a transaction of their own first. The pool's `RESET factory.tenant_id` would not be run by the pooler. If a pooler is added, ADR 0012 asks for a superseding record and the `rls` and `pool_reset` tests need to run through it.

## 6. The costs the ADR named for this package

| Cost named in ADR 0012 | Result |
|---|---|
| "every tenant transaction makes one more statement. The cost is one round trip and is measured in `s1-database-review`." | A tenant transaction makes **two** statements before its own: `set_config('factory.tenant_id', ...)` and a second `set_config` for the two timeouts. Measured on loopback, with nothing else in the transaction: 
  | Transaction on loopback (7 rounds of 3,000, variants interleaved) | p50 ms | p95 ms |
  |---|---:|---:|
  | `BEGIN`, `SELECT 1`, `COMMIT` | 0.068 | 0.100 |
  | and one `set_config` for the tenant | 0.094 | 0.113 |
  | and a second `set_config` for the limits (what `Store::begin` sends) | 0.119 | 0.164 |
  | the tenant and the limits in one statement | 0.095 | 0.132 |

  A round trip costs about **25 microseconds** here. The two statements add 51 to a transaction that is 68 bare; one statement would add 27. The saving, 24 microseconds on loopback, is one round trip: 0.3 to 1 ms across a network. The saving of merging the three settings into one statement is one round trip, about 15 to 30 microseconds here and the length of a round trip on a network (0.3 to 1 ms across a zone). That is a change in `tx.rs`, which this package may not edit. |
| "the claim and sweep plans" | The claim plan is the same with the policy on or off (system role, `USING (true)`). The sweep plans are unchanged by the policy; the expired-lease sweep changed with migration 19 for another reason. |
| "the query plans with RLS on 10,000 and 100,000 rows" | Section 3. |
