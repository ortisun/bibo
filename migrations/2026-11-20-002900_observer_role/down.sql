DO $$
DECLARE
  observed_table text;
BEGIN
  FOREACH observed_table IN ARRAY ARRAY[
    'tenants', 'repositories', 'principals', 'api_tokens', 'artifacts', 'webhook_deliveries', 'jobs',
    'stage_runs', 'attempts', 'task_nodes', 'ledger_entries', 'audit_events', 'outbox', 'inbox', 'approvals'
  ] LOOP
    EXECUTE format('DROP POLICY IF EXISTS observer_read ON public.%I', observed_table);
  END LOOP;
END
$$;

-- A table-level REVOKE takes the column privileges of the table with it.
REVOKE ALL ON tenants, repositories, principals, api_tokens, artifacts, webhook_deliveries, jobs, stage_runs,
              attempts, task_nodes, ledger_entries, audit_events, outbox, inbox, approvals,
              state_machine_states, state_machine_transitions, state_machine_edges
  FROM factory_observer;
DO $$
BEGIN
  IF to_regclass('public.__diesel_schema_migrations') IS NOT NULL THEN
    REVOKE ALL ON public.__diesel_schema_migrations FROM factory_observer;
  END IF;
END
$$;

-- The role and its membership of pg_read_all_stats are cluster wide and may serve other databases, so they
-- stay, as the groups of migration 11 do. Only what this migration granted in this database is taken back.
REVOKE USAGE ON SCHEMA public FROM factory_observer;
