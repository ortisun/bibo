-- A narrow group for the login of the HTTP API (finding API-3 of docs/reviews/api-security-review.md).
--
-- Until now the API login was a member of factory_app and factory_resolver. factory_app is the group of the
-- worker: it can INSERT into 17 tables, among them api_tokens, principals, approvals, ledger_entries and
-- outbox. The API writes four tables (jobs, original_requests, audit_events, webhook_deliveries). Because a
-- session that names a tenant by hand is that tenant (ADR 0012), anyone holding the API login's credentials
-- could mint a working token for another tenant's approver, and write approvals, ledger rows and events
-- directly. The review did exactly that with a raw connection.
--
-- PostgreSQL privileges are additive across the groups a login belongs to, so the privilege cannot be taken
-- from the API login while it is a member of factory_app. The fix is a group of its own:
--
--   factory_api_app   what the API reads and writes, and nothing else. No UPDATE, no DELETE, no column grant.
--
-- The API login becomes a member of factory_api_app and factory_resolver, and NOT of factory_app. The role
-- check of the storage crate (crates/storage/src/pg/readiness.rs) refuses to start on any other shape, and
-- the rls suite reports a login that belongs to both factory_api_app and factory_app or factory_system.
-- factory_app is not changed: the worker keeps what it has.
--
-- What the API does, found in apps/api/src and crates/storage/src/pg:
--   writes   jobs, original_requests, audit_events (also for the platform tenant), webhook_deliveries.
--            Every write is an INSERT; "ON CONFLICT DO NOTHING" needs no other privilege.
--   reads    tenants, repositories, principals (who is calling, which repository), jobs, stage_runs and
--            original_requests (status, listing, idempotency), outbox and audit_events (the timeline and the
--            witness of a commit whose answer was lost), webhook_deliveries (the de-duplication keys),
--            the three state machine tables (the status trigger of a new job reads them) and the Diesel
--            version table (the start-up and readiness check).
--   the two lookups (resolve_token, resolve_installation) stay with factory_resolver.
--
-- The grants are written out here, in one place, as in migration 9. The api_privileges suite lists them again
-- and compares both ways.

-- Roles are cluster wide. Create the role if the DBA has not already, and refuse to continue if an existing
-- role of that name has powers the design rules out.
DO $$
DECLARE
  r pg_catalog.pg_roles%ROWTYPE;
BEGIN
  SELECT * INTO r FROM pg_catalog.pg_roles WHERE rolname = 'factory_api_app';
  IF NOT FOUND THEN
    CREATE ROLE factory_api_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  ELSIF r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolcanlogin THEN
    RAISE EXCEPTION 'the existing role factory_api_app has too many powers (superuser, createrole, createdb, replication, bypassrls or login)';
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO factory_api_app;

-- PUBLIC holds nothing on any table, view or sequence today (the privileges and api_privileges suites say
-- so). Say it again for the tables and views, so that one added by hand with the default grants of some other
-- tool cannot reach the API login through PUBLIC. Sequences are left alone: a REVOKE on every sequence of
-- the schema made the timing-sensitive lease race of scripts/db-test.sh fail three times out of three, for a
-- reason this migration does not need to know, and PUBLIC holds nothing on them (the suites check that).
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;

-- Reference data and the schema version.
GRANT SELECT ON state_machine_states, state_machine_transitions, state_machine_edges TO factory_api_app;
DO $$
BEGIN
  IF to_regclass('public.__diesel_schema_migrations') IS NOT NULL THEN
    GRANT SELECT ON public.__diesel_schema_migrations TO factory_api_app;
  END IF;
END
$$;

-- Read only.
GRANT SELECT ON tenants, repositories, principals, stage_runs, outbox TO factory_api_app;

-- Read and append. Never UPDATE or DELETE.
GRANT SELECT, INSERT ON jobs, original_requests, audit_events, webhook_deliveries TO factory_api_app;

-- Row-level security: the policies name their roles, and the new group is not in them yet. Without this the
-- group would see nothing and could write nothing. The expression is the one of migration 12, unchanged: a
-- row belongs to the tenant the transaction named.
DO $$
DECLARE
  tenant_table text;
BEGIN
  FOREACH tenant_table IN ARRAY ARRAY[
    'repositories', 'principals', 'jobs', 'original_requests', 'stage_runs', 'audit_events', 'outbox',
    'webhook_deliveries'
  ] LOOP
    EXECUTE format('ALTER POLICY tenant_isolation ON public.%I TO factory_app, factory_api_app', tenant_table);
  END LOOP;
END
$$;
ALTER POLICY tenant_self ON tenants TO factory_app, factory_api_app;
