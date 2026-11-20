-- Row-level security, part 2 of 4: tenant isolation (ADR 0012, sections 1 and 2).
--
-- Every tenant-owned table gets ENABLE and FORCE ROW LEVEL SECURITY and one policy for factory_app:
--
--   tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid
--
-- for all commands, the same expression for USING and WITH CHECK.
--
--   * Store::begin makes the setting with set_config('factory.tenant_id', $1, true) as the first
--     statement of each transaction. The third argument ties it to the transaction.
--   * current_setting(..., true) returns NULL when the setting was never made. After a transaction that
--     made it has ended, the next transaction on the same connection reads it as an EMPTY STRING, not NULL
--     (measured on PostgreSQL 18.6). Cast to uuid, the empty string raises "invalid input syntax" and the
--     failure would then depend on what ran before on that connection. NULLIF turns it into NULL, the
--     comparison is never true, and the session sees nothing and gets no error. A value that is not a uuid
--     still raises 22P02: a bug in the caller fails loudly instead of being quietly empty.
--   * FORCE makes the table owner subject to the policy too. The policy names factory_app only, so the
--     owner sees no row and can write none unless it becomes a member of factory_app. A migration that
--     must touch tenant rows has to say so (docs/database/migration-safety.md).
--   * Foreign key checks, unique index checks and the deferred constraint triggers bypass row security by
--     PostgreSQL's design for the referential checks. The composite keys that carry tenant_id stay for
--     that reason: they catch a wrong tenant on a WRITE, which this policy cannot (it sees one row, not
--     its parent). docs/database/tenancy.md records the test of this claim on this schema.
--
-- The `tenants` table has no tenant_id column. A tenant session may read its own row and no other: a
-- tenant's slug and display name are another tenant's business. It is ENABLEd but not FORCEd, because
-- onboarding a tenant (an INSERT into tenants) is an action of the owner role, and the application role
-- has only SELECT on it.
--
-- The four reference tables (the three state machine tables and the Diesel version table) hold no tenant
-- data and keep no policy. factory_app has SELECT on them, nothing else.

DO $$
DECLARE
  tenant_table text;
BEGIN
  FOREACH tenant_table IN ARRAY ARRAY[
    'repositories', 'principals', 'api_tokens', 'artifacts', 'webhook_deliveries', 'jobs', 'original_requests',
    'stage_runs', 'stage_run_artifacts', 'attempts', 'task_nodes', 'task_node_dependencies', 'ledger_entries',
    'audit_events', 'outbox', 'inbox', 'approvals'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', tenant_table);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', tenant_table);
    EXECUTE format($policy$
      CREATE POLICY tenant_isolation ON public.%I
        AS PERMISSIVE FOR ALL TO factory_app
        USING (tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid)
        WITH CHECK (tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid)
    $policy$, tenant_table);
  END LOOP;
END
$$;

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_self ON tenants
  AS PERMISSIVE FOR SELECT TO factory_app
  USING (id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid);
