-- Takes the three reads back: the API login reads the tables of migration 2026-10-28-002000 again and no more.
DO $$
DECLARE
  evidence_table text;
BEGIN
  FOREACH evidence_table IN ARRAY ARRAY['artifacts', 'stage_run_artifacts', 'ledger_entries'] LOOP
    EXECUTE format('ALTER POLICY tenant_isolation ON public.%I TO factory_app', evidence_table);
  END LOOP;
END
$$;

REVOKE SELECT ON artifacts, stage_run_artifacts, ledger_entries FROM factory_api_app;
