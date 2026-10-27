DO $$
BEGIN
  IF to_regclass('public.__diesel_schema_migrations') IS NOT NULL THEN
    REVOKE ALL ON public.__diesel_schema_migrations FROM factory_app;
  END IF;
END
$$;

REVOKE ALL ON
  state_machine_states, state_machine_transitions, state_machine_edges,
  tenants, repositories, principals, api_tokens, active_api_tokens,
  artifacts, stage_run_artifacts, webhook_deliveries, original_requests,
  jobs, stage_runs, attempts, task_nodes, task_node_dependencies,
  ledger_entries, ledger_current_claims, ledger_assurance_levels, audit_events,
  outbox, inbox, approvals
FROM factory_app;
