DROP POLICY IF EXISTS tenant_self ON tenants;
ALTER TABLE tenants DISABLE ROW LEVEL SECURITY;

DO $$
DECLARE
  tenant_table text;
BEGIN
  FOREACH tenant_table IN ARRAY ARRAY[
    'repositories', 'principals', 'api_tokens', 'artifacts', 'webhook_deliveries', 'jobs', 'original_requests',
    'stage_runs', 'stage_run_artifacts', 'attempts', 'task_nodes', 'task_node_dependencies', 'ledger_entries',
    'audit_events', 'outbox', 'inbox', 'approvals'
  ] LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON public.%I', tenant_table);
    EXECUTE format('ALTER TABLE public.%I NO FORCE ROW LEVEL SECURITY', tenant_table);
    EXECUTE format('ALTER TABLE public.%I DISABLE ROW LEVEL SECURITY', tenant_table);
  END LOOP;
END
$$;
