-- Suite: privileges
-- Proves the application role has exactly the grants listed in
-- migrations/2026-10-27-000900_application_privileges and nothing else, that it owns nothing, has no
-- special powers, and that PUBLIC has no access to any table. The expected list below is written out
-- here on purpose: a change to a grant must change this file, and that shows up in review.

-- ---------------------------------------------------------------------------------------------
-- 1. The role itself.

DO $$
DECLARE
  r pg_roles%ROWTYPE;
BEGIN
  SELECT * INTO r FROM pg_roles WHERE rolname = 'factory_app';
  PERFORM dbtest.expect_true('factory_app exists', FOUND);
  PERFORM dbtest.expect_true('factory_app cannot log in (a login role is made a member of it by the deployment)', NOT r.rolcanlogin);
  PERFORM dbtest.expect_true('factory_app is not a superuser', NOT r.rolsuper);
  PERFORM dbtest.expect_true('factory_app cannot create roles', NOT r.rolcreaterole);
  PERFORM dbtest.expect_true('factory_app cannot create databases', NOT r.rolcreatedb);
  PERFORM dbtest.expect_true('factory_app cannot replicate', NOT r.rolreplication);
  PERFORM dbtest.expect_true('factory_app does not bypass row-level security', NOT r.rolbypassrls);
  PERFORM dbtest.expect_eq('factory_app is a member of no role', (SELECT count(*) FROM pg_auth_members WHERE member = r.oid), 0::bigint);
  PERFORM dbtest.expect_eq('factory_app owns no table, view, sequence or index',
    (SELECT count(*) FROM pg_class WHERE relowner = r.oid), 0::bigint);
  PERFORM dbtest.expect_eq('factory_app owns no function', (SELECT count(*) FROM pg_proc WHERE proowner = r.oid), 0::bigint);
  PERFORM dbtest.expect_eq('factory_app owns no schema', (SELECT count(*) FROM pg_namespace WHERE nspowner = r.oid), 0::bigint);
  PERFORM dbtest.expect_true('factory_app may use the public schema', has_schema_privilege('factory_app', 'public', 'USAGE'));
  PERFORM dbtest.expect_true('factory_app may not create in the public schema', NOT has_schema_privilege('factory_app', 'public', 'CREATE'));
  PERFORM dbtest.expect_true('factory_app may not create in the database', NOT has_database_privilege('factory_app', current_database(), 'CREATE'));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. Table-level grants equal the list, both ways.

CREATE TEMP TABLE expected_table_grants (tbl text, privilege text);
INSERT INTO expected_table_grants VALUES
  ('state_machine_states', 'SELECT'), ('state_machine_transitions', 'SELECT'), ('state_machine_edges', 'SELECT'),
  ('__diesel_schema_migrations', 'SELECT'),
  ('tenants', 'SELECT'),
  ('repositories', 'SELECT'), ('repositories', 'INSERT'),
  ('principals', 'SELECT'), ('principals', 'INSERT'),
  ('api_tokens', 'SELECT'), ('api_tokens', 'INSERT'), ('active_api_tokens', 'SELECT'),
  ('artifacts', 'SELECT'), ('artifacts', 'INSERT'),
  ('stage_run_artifacts', 'SELECT'), ('stage_run_artifacts', 'INSERT'),
  ('webhook_deliveries', 'SELECT'), ('webhook_deliveries', 'INSERT'),
  ('original_requests', 'SELECT'), ('original_requests', 'INSERT'),
  ('jobs', 'SELECT'), ('jobs', 'INSERT'),
  ('stage_runs', 'SELECT'), ('stage_runs', 'INSERT'),
  ('attempts', 'SELECT'), ('attempts', 'INSERT'),
  ('task_nodes', 'SELECT'), ('task_nodes', 'INSERT'),
  ('task_node_dependencies', 'SELECT'), ('task_node_dependencies', 'INSERT'),
  ('ledger_entries', 'SELECT'), ('ledger_entries', 'INSERT'),
  ('ledger_current_claims', 'SELECT'), ('ledger_assurance_levels', 'SELECT'),
  ('audit_events', 'SELECT'), ('audit_events', 'INSERT'),
  ('outbox', 'SELECT'), ('outbox', 'INSERT'),
  ('inbox', 'SELECT'), ('inbox', 'INSERT'),
  ('approvals', 'SELECT'), ('approvals', 'INSERT');

-- Column-level UPDATE grants. Anything not listed cannot be updated by the application role.
CREATE TEMP TABLE expected_column_grants (tbl text, col text);
INSERT INTO expected_column_grants VALUES
  ('repositories', 'default_branch'), ('repositories', 'enabled'), ('repositories', 'protection_preflight_passed'),
  ('repositories', 'autonomy_ceiling'), ('repositories', 'version'),
  ('principals', 'login'), ('principals', 'disabled_at'),
  ('api_tokens', 'revoked_at'), ('api_tokens', 'last_used_at'),
  ('jobs', 'status'), ('jobs', 'version'), ('jobs', 'policy_hash'), ('jobs', 'normalized_request_sha256'),
  ('jobs', 'ledger_head_sequence'), ('jobs', 'ledger_head_hash'), ('jobs', 'terminal_at'),
  ('stage_runs', 'status'), ('stage_runs', 'version'), ('stage_runs', 'lease_epoch'), ('stage_runs', 'max_attempts'),
  ('stage_runs', 'not_before'), ('stage_runs', 'stage_contract_sha256'), ('stage_runs', 'gate_outcome'),
  ('stage_runs', 'gate_report_sha256'), ('stage_runs', 'finished_at'), ('stage_runs', 'superseded_at'), ('stage_runs', 'failing_set_sha256'),
  ('repositories', 'bypass_attested_by_principal_id'), ('repositories', 'bypass_attested_at'),
  ('attempts', 'status'), ('attempts', 'version'), ('attempts', 'lease_owner'), ('attempts', 'lease_expires_at'),
  ('attempts', 'last_heartbeat_at'), ('attempts', 'deadline_at'), ('attempts', 'teardown_deadline_at'),
  ('attempts', 'failure_class'), ('attempts', 'output_sha256'), ('attempts', 'sandbox_id'), ('attempts', 'sandbox_leaked'),
  ('attempts', 'ended_at'),
  ('task_nodes', 'status'), ('task_nodes', 'version'), ('task_nodes', 'retry_count'), ('task_nodes', 'current_attempt_id'),
  ('task_nodes', 'commit_sha'), ('task_nodes', 'finished_at'),
  ('outbox', 'published_at'), ('outbox', 'publish_attempts'),
  ('approvals', 'invalidated_at'), ('approvals', 'invalidation_reason');

DO $$
DECLARE
  extra text;
  missing text;
BEGIN
  SELECT string_agg(c.relname || ':' || a.privilege_type, ', ' ORDER BY c.relname, a.privilege_type) INTO extra
    FROM pg_class c, aclexplode(c.relacl) a
   WHERE c.relnamespace = 'public'::regnamespace AND a.grantee = 'factory_app'::regrole
     AND NOT EXISTS (SELECT 1 FROM expected_table_grants e WHERE e.tbl = c.relname AND e.privilege = a.privilege_type);
  PERFORM dbtest.expect_eq('factory_app holds no table privilege beyond the expected list', coalesce(extra, ''), '');

  SELECT string_agg(e.tbl || ':' || e.privilege, ', ' ORDER BY e.tbl, e.privilege) INTO missing
    FROM expected_table_grants e
   WHERE NOT EXISTS (SELECT 1 FROM pg_class c, aclexplode(c.relacl) a
                      WHERE c.relnamespace = 'public'::regnamespace AND c.relname = e.tbl AND a.grantee = 'factory_app'::regrole AND a.privilege_type = e.privilege);
  PERFORM dbtest.expect_eq('factory_app holds every table privilege on the expected list', coalesce(missing, ''), '');

  SELECT string_agg(c.relname || '.' || att.attname || ':' || a.privilege_type, ', ' ORDER BY c.relname, att.attname) INTO extra
    FROM pg_attribute att
    JOIN pg_class c ON c.oid = att.attrelid AND c.relnamespace = 'public'::regnamespace, aclexplode(att.attacl) a
   WHERE a.grantee = 'factory_app'::regrole
     AND NOT (a.privilege_type = 'UPDATE' AND EXISTS (SELECT 1 FROM expected_column_grants e WHERE e.tbl = c.relname AND e.col = att.attname));
  PERFORM dbtest.expect_eq('factory_app holds no column privilege beyond the expected UPDATE list', coalesce(extra, ''), '');

  SELECT string_agg(e.tbl || '.' || e.col, ', ' ORDER BY e.tbl, e.col) INTO missing
    FROM expected_column_grants e
   WHERE NOT EXISTS (SELECT 1 FROM pg_attribute att JOIN pg_class c ON c.oid = att.attrelid AND c.relnamespace = 'public'::regnamespace, aclexplode(att.attacl) a
                      WHERE c.relname = e.tbl AND att.attname = e.col AND a.grantee = 'factory_app'::regrole AND a.privilege_type = 'UPDATE');
  PERFORM dbtest.expect_eq('factory_app holds every column UPDATE privilege on the expected list', coalesce(missing, ''), '');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. Nobody else, and nothing destructive.

DO $$
DECLARE
  offenders text;
BEGIN
  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO offenders
    FROM pg_class c, aclexplode(c.relacl) a
   WHERE c.relnamespace = 'public'::regnamespace AND a.grantee = 0;
  PERFORM dbtest.expect_eq('PUBLIC holds no privilege on any table, view or sequence', coalesce(offenders, ''), '');

  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO offenders
    FROM pg_class c, aclexplode(c.relacl) a
   WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'v') AND a.grantee = 'factory_app'::regrole
     AND a.privilege_type IN ('DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER');
  PERFORM dbtest.expect_eq('factory_app has no DELETE, TRUNCATE, REFERENCES or TRIGGER privilege on anything', coalesce(offenders, ''), '');

  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO offenders
    FROM pg_class c, aclexplode(c.relacl) a
   WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'S' AND a.grantee = 'factory_app'::regrole;
  PERFORM dbtest.expect_eq('factory_app holds no sequence privilege (identity columns need none)', coalesce(offenders, ''), '');

  -- The append-only tables: the application role can only INSERT and SELECT, at table and column level.
  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO offenders
    FROM pg_class c
   WHERE c.relnamespace = 'public'::regnamespace
     AND c.relname IN ('ledger_entries', 'audit_events', 'original_requests', 'artifacts', 'webhook_deliveries', 'inbox', 'stage_run_artifacts', 'task_node_dependencies')
     AND has_any_column_privilege('factory_app', c.oid, 'UPDATE');
  PERFORM dbtest.expect_eq('the record-of-fact tables can not be updated at all by the application role', coalesce(offenders, ''), '');
END
$$;

-- The unexpected approach: try the forbidden things as the application role.
DO $$
BEGIN
  PERFORM dbtest.expect_error('factory_app cannot create a role', 'CREATE ROLE sneaky', '42501', 'factory_app');
  -- Where it holds some privilege on a table, PostgreSQL only warns about a GRANT it may not make, and grants nothing.
  PERFORM dbtest.exec('GRANT DELETE ON jobs TO factory_app', 'factory_app');
  PERFORM dbtest.expect_true('a GRANT of DELETE run by factory_app on jobs changes nothing', NOT has_table_privilege('factory_app', 'jobs', 'DELETE'));
  PERFORM dbtest.exec('GRANT SELECT ON tenants TO PUBLIC', 'factory_app');
  PERFORM dbtest.expect_true('a GRANT to PUBLIC run by factory_app changes nothing',
    NOT EXISTS (SELECT 1 FROM pg_class c, aclexplode(c.relacl) a WHERE c.relname = 'tenants' AND a.grantee = 0));
  PERFORM dbtest.expect_error('factory_app cannot turn row-level security on or off', 'ALTER TABLE jobs DISABLE ROW LEVEL SECURITY', '42501', 'factory_app');
  -- The setting that switches every trigger and foreign key off. The tests use it as a superuser to tamper.
  PERFORM dbtest.expect_error('factory_app cannot switch triggers and foreign keys off (session_replication_role)',
    'SET session_replication_role = replica', '42501', 'factory_app');
  PERFORM dbtest.expect_error('factory_app cannot switch triggers and foreign keys off through set_config either',
    'SELECT set_config(''session_replication_role'', ''replica'', true)', '42501', 'factory_app');
  PERFORM dbtest.expect_error('factory_app cannot read files on the database server', 'SELECT pg_read_file(''/etc/hosts'')', '42501', 'factory_app');
  PERFORM dbtest.expect_ok('factory_app can read the migration version table for the start-up schema check', 'SELECT max(version) FROM __diesel_schema_migrations', 'factory_app');
  PERFORM dbtest.expect_error('factory_app cannot change the migration version table', 'DELETE FROM __diesel_schema_migrations', '42501', 'factory_app');
  PERFORM dbtest.expect_error('factory_app cannot change the state machine reference data',
    'UPDATE state_machine_edges SET from_status = from_status', '42501', 'factory_app');
  PERFORM dbtest.expect_error('factory_app cannot insert into the state machine reference data',
    'INSERT INTO state_machine_states VALUES (''job'', ''HACKED'', false, false)', '42501', 'factory_app');
  PERFORM dbtest.expect_error('factory_app cannot create tenants (onboarding is an owner action)',
    format($q$INSERT INTO tenants (id, slug, display_name) VALUES (%L, 'rogue', 'Rogue')$q$, dbtest.u(666)), '42501', 'factory_app');
END
$$;

-- A real login is a member of factory_app. It must not be able to become the owner. (This test session is
-- a superuser, which could switch to anyone, so the check is made as a login that is only a member.)
BEGIN;
CREATE ROLE privilege_test_login LOGIN IN ROLE factory_app;
SELECT dbtest.expect_error('a login that is a member of factory_app cannot switch to the owner role',
  'SET LOCAL SESSION AUTHORIZATION privilege_test_login; SET ROLE postgres', '42501');
SELECT dbtest.expect_error('and it cannot switch to a predefined role with broad read rights',
  'SET LOCAL SESSION AUTHORIZATION privilege_test_login; SET ROLE pg_read_all_data', '42501');
ROLLBACK;
SELECT dbtest.expect_eq('the test login was rolled back', (SELECT count(*) FROM pg_roles WHERE rolname = 'privilege_test_login'), 0::bigint);
