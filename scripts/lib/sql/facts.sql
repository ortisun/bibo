-- The facts a backup records and a restore must reproduce (work package s1-local-deployment).
--
-- Run as the database superuser (the owner role cannot see rows under FORCE ROW LEVEL SECURITY; a
-- superuser bypasses row-level security, so the chain verifiers and the counts see every tenant).
-- Prints one JSON document on one line. Nothing here writes to the database.
--
-- A "fingerprint" is the SHA-256 of a sorted list of text lines that describe one kind of catalog
-- object. The same query on the restored database must print the same hash. When it does not, the
-- name of the fingerprint says which kind of object changed.

SET TimeZone = 'UTC';

WITH
-- The schemas that belong to the factory. The system schemas and the throwaway test-helper schema
-- are left out.
sch AS (
  SELECT n.oid, n.nspname FROM pg_namespace n
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast', 'dbtest')
     AND n.nspname NOT LIKE 'pg\_temp\_%' AND n.nspname NOT LIKE 'pg\_toast\_temp\_%'
),
fp_tables AS (
  SELECT s.nspname || '.' || c.relname || '|' || c.relkind::text || '|' || c.relowner::regrole::text || '|' ||
         coalesce(c.relacl::text, '') || '|rls=' || c.relrowsecurity || '|force=' || c.relforcerowsecurity AS line
    FROM pg_class c JOIN sch s ON s.oid = c.relnamespace
   WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S')
),
fp_columns AS (
  SELECT s.nspname || '.' || c.relname || '.' || a.attname || '|' || a.attacl::text AS line
    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN sch s ON s.oid = c.relnamespace
   WHERE a.attacl IS NOT NULL AND NOT a.attisdropped
),
fp_functions AS (
  SELECT s.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')|' ||
         p.proowner::regrole::text || '|' || coalesce(p.proacl::text, '') || '|secdef=' || p.prosecdef ||
         '|config=' || coalesce(p.proconfig::text, '') AS line
    FROM pg_proc p JOIN sch s ON s.oid = p.pronamespace
),
fp_schemas AS (
  SELECT s.nspname || '|' || n.nspowner::regrole::text || '|' || coalesce(n.nspacl::text, '') AS line
    FROM sch s JOIN pg_namespace n ON n.oid = s.oid
),
fp_default_acl AS (
  SELECT d.defaclrole::regrole::text || '|' || d.defaclobjtype::text || '|' || d.defaclacl::text AS line
    FROM pg_default_acl d
),
fp_policies AS (
  SELECT s.nspname || '.' || c.relname || '|' || p.polname || '|' || p.polcmd::text || '|' || p.polpermissive ||
         '|' || coalesce((SELECT string_agg(CASE WHEN r = 0 THEN 'PUBLIC' ELSE r::regrole::text END, ',' ORDER BY r)
                            FROM unnest(p.polroles) AS r), '') ||
         '|' || coalesce(pg_get_expr(p.polqual, p.polrelid), '') ||
         '|' || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') AS line
    FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN sch s ON s.oid = c.relnamespace
),
fp_triggers AS (
  SELECT s.nspname || '.' || c.relname || '|' || t.tgname || '|' || t.tgenabled::text || '|' || pg_get_triggerdef(t.oid) AS line
    FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN sch s ON s.oid = c.relnamespace
   WHERE NOT t.tgisinternal
),
fp_constraints AS (
  -- The text of a CHECK expression is not stable across a dump and a restore: PostgreSQL prints the same
  -- chain of AND with different brackets after it has been parsed again (seen on jobs_pipeline_scope_check).
  -- So brackets are left out of CHECK definitions. Every name, operator and value still counts.
  SELECT s.nspname || '.' || c.relname || '|' || k.conname || '|' ||
         CASE WHEN k.contype = 'c' THEN regexp_replace(pg_get_constraintdef(k.oid), '[()]', '', 'g')
              ELSE pg_get_constraintdef(k.oid) END AS line
    FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN sch s ON s.oid = c.relnamespace
),
fp_indexes AS (
  SELECT schemaname || '.' || tablename || '|' || indexdef AS line
    FROM pg_indexes WHERE schemaname IN (SELECT nspname FROM sch)
),
chains AS (
  SELECT DISTINCT tenant_id AS t, job_id AS j FROM ledger_entries
),
audit_tenants AS (
  SELECT DISTINCT tenant_id AS t FROM audit_events
)
SELECT jsonb_build_object(
  'server_version', current_setting('server_version'),
  'server_version_num', current_setting('server_version_num')::int,
  'schema', (SELECT jsonb_build_object('migrations', count(*), 'latest', max(version))
               FROM __diesel_schema_migrations),
  'roles', (SELECT coalesce(jsonb_agg(jsonb_build_object(
              'name', r.rolname, 'login', r.rolcanlogin, 'super', r.rolsuper, 'createdb', r.rolcreatedb,
              'createrole', r.rolcreaterole, 'replication', r.rolreplication, 'bypassrls', r.rolbypassrls,
              'inherit', r.rolinherit, 'conn_limit', r.rolconnlimit,
              'member_of', (SELECT coalesce(jsonb_agg(g.rolname || ':inherit=' || m.inherit_option ||
                                                      ':set=' || m.set_option || ':admin=' || m.admin_option
                                                      ORDER BY g.rolname), '[]'::jsonb)
                              FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                             WHERE m.member = r.oid)
            ) ORDER BY r.rolname), '[]'::jsonb)
            FROM pg_roles r WHERE r.rolname LIKE 'factory\_%'),
  'fingerprints', jsonb_build_object(
    'tables',      (SELECT encode(sha256(convert_to(coalesce(string_agg(line, E'\n' ORDER BY line), ''), 'UTF8')), 'hex') FROM fp_tables),
    'columns',     (SELECT encode(sha256(convert_to(coalesce(string_agg(line, E'\n' ORDER BY line), ''), 'UTF8')), 'hex') FROM fp_columns),
    'functions',   (SELECT encode(sha256(convert_to(coalesce(string_agg(line, E'\n' ORDER BY line), ''), 'UTF8')), 'hex') FROM fp_functions),
    'schemas',     (SELECT encode(sha256(convert_to(coalesce(string_agg(line, E'\n' ORDER BY line), ''), 'UTF8')), 'hex') FROM fp_schemas),
    'default_acl', (SELECT encode(sha256(convert_to(coalesce(string_agg(line, E'\n' ORDER BY line), ''), 'UTF8')), 'hex') FROM fp_default_acl),
    'policies',    (SELECT encode(sha256(convert_to(coalesce(string_agg(line, E'\n' ORDER BY line), ''), 'UTF8')), 'hex') FROM fp_policies),
    'triggers',    (SELECT encode(sha256(convert_to(coalesce(string_agg(line, E'\n' ORDER BY line), ''), 'UTF8')), 'hex') FROM fp_triggers),
    'constraints', (SELECT encode(sha256(convert_to(coalesce(string_agg(line, E'\n' ORDER BY line), ''), 'UTF8')), 'hex') FROM fp_constraints),
    'indexes',     (SELECT encode(sha256(convert_to(coalesce(string_agg(line, E'\n' ORDER BY line), ''), 'UTF8')), 'hex') FROM fp_indexes)
  ),
  -- The head of each chain: the last sequence number and its hash. A chain that lost its tail still
  -- verifies on its own (docs/database/ledger-and-audit.md), so the head is recorded to catch that.
  'heads', jsonb_build_object(
    'ledger', (SELECT coalesce(jsonb_agg(jsonb_build_object('tenant', e.tenant_id, 'job', e.job_id,
                  'sequence', e.sequence, 'hash', e.entry_hash) ORDER BY e.tenant_id, e.job_id), '[]'::jsonb)
                 FROM ledger_entries e
                WHERE e.sequence = (SELECT max(x.sequence) FROM ledger_entries x
                                     WHERE x.tenant_id = e.tenant_id AND x.job_id = e.job_id)),
    'audit', (SELECT coalesce(jsonb_agg(jsonb_build_object('tenant', a.tenant_id, 'sequence', a.sequence,
                  'hash', a.hash) ORDER BY a.tenant_id), '[]'::jsonb)
                FROM audit_events a
               WHERE a.sequence = (SELECT max(x.sequence) FROM audit_events x WHERE x.tenant_id = a.tenant_id))
  ),
  -- The database's own verifiers. NULL means the chain is sound; a number is the first bad sequence.
  'chain', jsonb_build_object(
    'ledger_chains', (SELECT count(*) FROM chains),
    'ledger_bad', (SELECT coalesce(jsonb_agg(jsonb_build_object('tenant', t, 'job', j,
                      'first_bad', ledger_verify_chain(t, j)) ORDER BY t, j), '[]'::jsonb)
                     FROM chains WHERE ledger_verify_chain(t, j) IS NOT NULL),
    'audit_chains', (SELECT count(*) FROM audit_tenants),
    'audit_bad', (SELECT coalesce(jsonb_agg(jsonb_build_object('tenant', t,
                      'first_bad', audit_verify_chain(t)) ORDER BY t), '[]'::jsonb)
                    FROM audit_tenants WHERE audit_verify_chain(t) IS NOT NULL)
  ),
  -- Every artifact the index says the local disk holds. A restore checks that each one has a blob.
  'artifact_rows', (SELECT coalesce(jsonb_agg(DISTINCT content_sha256 ORDER BY content_sha256), '[]'::jsonb)
                      FROM artifacts WHERE backend = 'local-fs'),
  'sessions', (SELECT count(*) FROM pg_stat_activity
                WHERE usename IN ('factory_api', 'factory_worker', 'factory_engine'))
)::text;
