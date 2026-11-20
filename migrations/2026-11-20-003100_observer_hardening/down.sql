-- Back to the observer of migration 002900. Run as a superuser, as the up script.

GRANT SELECT (github_installation_id, github_repository_id) ON repositories TO factory_observer;
GRANT SELECT (github_installation_id, github_repository_id) ON webhook_deliveries TO factory_observer;

DO $$
DECLARE
  f regprocedure;
  audit_owner text;
BEGIN
  SELECT pg_catalog.pg_get_userbyid(c.relowner) INTO audit_owner
    FROM pg_catalog.pg_class c WHERE c.oid = 'public.audit_events'::regclass;
  REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint) FROM factory_app, factory_api_app;
  REVOKE EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_lock(bigint), pg_catalog.pg_advisory_unlock(bigint) FROM factory_app;
  EXECUTE pg_catalog.format('REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint) FROM %I', audit_owner);
  FOR f IN
    SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p
     WHERE p.pronamespace = 'pg_catalog'::regnamespace
       AND (p.proname LIKE 'pg\_advisory\_%' OR p.proname LIKE 'pg\_try\_advisory\_%')
     ORDER BY p.oid
  LOOP
    EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION %s TO PUBLIC', f);
  END LOOP;
END
$$;

DROP FUNCTION observer_statements();
DROP FUNCTION observer_lock_waits();
DROP FUNCTION observer_activity();
DROP FUNCTION observer_normalize_query(text, integer);
REVOKE USAGE ON SCHEMA public FROM factory_observer_stats;

-- Roles and memberships are cluster wide. The observer gets back what migration 002900 gave it, so that this
-- database's tools work as they did; a database of the same cluster still at 003100 then shares it until its next
-- migration. factory_observer_stats stays, as every group does, and keeps its membership: it may own the functions
-- of another database.
ALTER ROLE factory_observer INHERIT;
GRANT pg_read_all_stats TO factory_observer;
