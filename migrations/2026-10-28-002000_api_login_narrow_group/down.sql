-- The role is cluster wide and may carry grants in other databases, so it stays, as factory_app does. Its
-- grants and its place in the policies are taken back. The PUBLIC revoke is not undone: PUBLIC held nothing
-- before it.
ALTER POLICY tenant_self ON tenants TO factory_app;
DO $$
DECLARE
  tenant_table text;
BEGIN
  FOREACH tenant_table IN ARRAY ARRAY[
    'repositories', 'principals', 'jobs', 'original_requests', 'stage_runs', 'audit_events', 'outbox',
    'webhook_deliveries'
  ] LOOP
    EXECUTE format('ALTER POLICY tenant_isolation ON public.%I TO factory_app', tenant_table);
  END LOOP;
END
$$;

DO $$
BEGIN
  IF to_regclass('public.__diesel_schema_migrations') IS NOT NULL THEN
    REVOKE ALL ON public.__diesel_schema_migrations FROM factory_api_app;
  END IF;
END
$$;

REVOKE ALL ON
  state_machine_states, state_machine_transitions, state_machine_edges,
  tenants, repositories, principals, stage_runs, outbox,
  jobs, original_requests, audit_events, webhook_deliveries
FROM factory_api_app;

REVOKE USAGE ON SCHEMA public FROM factory_api_app;
