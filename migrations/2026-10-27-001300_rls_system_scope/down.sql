DROP POLICY IF EXISTS system_relay ON outbox;
DROP POLICY IF EXISTS system_find ON outbox;
DROP POLICY IF EXISTS system_lock ON attempts;
DROP POLICY IF EXISTS system_find ON attempts;
DROP POLICY IF EXISTS system_find ON jobs;
DROP POLICY IF EXISTS system_lock ON stage_runs;
DROP POLICY IF EXISTS system_find ON stage_runs;

REVOKE ALL ON stage_runs, jobs, attempts, outbox FROM factory_system;
DO $$
BEGIN
  IF to_regclass('public.__diesel_schema_migrations') IS NOT NULL THEN
    REVOKE ALL ON public.__diesel_schema_migrations FROM factory_system;
  END IF;
END
$$;
