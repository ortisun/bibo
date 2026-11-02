-- Suite: api_privileges
-- Proves finding API-3 of docs/reviews/api-security-review.md is closed: the login of the HTTP API is a
-- member of its own narrow group, factory_api_app (with factory_resolver for the two lookups), and holds no
-- privilege that the API does not use. Before migration 2026-10-28-002000 it was a member of factory_app,
-- which can INSERT into 17 tables, among them api_tokens, principals, approvals, ledger_entries and outbox;
-- a session that names a tenant by hand is that tenant (ADR 0012), so the API login could mint a token for
-- another tenant's approver.
--
-- The expected list is written out here on purpose: a change to a grant must change this file, and that
-- shows up in review. The API writes four tables (jobs, original_requests, audit_events,
-- webhook_deliveries) and reads a few more; it deletes nothing. Since migration 2026-11-02-002400 it also
-- registers repositories and changes four columns of them (the project map and the enabled flag), by column
-- grants that this file lists on their own.

-- ---------------------------------------------------------------------------------------------
-- 1. The role itself.

DO $$
DECLARE
  r pg_roles%ROWTYPE;
BEGIN
  SELECT * INTO r FROM pg_roles WHERE rolname = 'factory_api_app';
  PERFORM dbtest.expect_true('factory_api_app exists', FOUND);
  PERFORM dbtest.expect_true('factory_api_app cannot log in (the API login is made a member of it by the deployment)', NOT r.rolcanlogin);
  PERFORM dbtest.expect_true('factory_api_app is not a superuser', NOT r.rolsuper);
  PERFORM dbtest.expect_true('factory_api_app cannot create roles', NOT r.rolcreaterole);
  PERFORM dbtest.expect_true('factory_api_app cannot create databases', NOT r.rolcreatedb);
  PERFORM dbtest.expect_true('factory_api_app cannot replicate', NOT r.rolreplication);
  PERFORM dbtest.expect_true('factory_api_app does not bypass row-level security', NOT r.rolbypassrls);
  PERFORM dbtest.expect_eq('factory_api_app is a member of no role (it must not inherit factory_app)',
    (SELECT count(*) FROM pg_auth_members WHERE member = r.oid), 0::bigint);
  PERFORM dbtest.expect_eq('factory_api_app owns no relation, function or schema',
    (SELECT count(*) FROM pg_class WHERE relowner = r.oid) + (SELECT count(*) FROM pg_proc WHERE proowner = r.oid)
      + (SELECT count(*) FROM pg_namespace WHERE nspowner = r.oid), 0::bigint);
  PERFORM dbtest.expect_true('factory_api_app may use the public schema', has_schema_privilege('factory_api_app', 'public', 'USAGE'));
  PERFORM dbtest.expect_true('factory_api_app may not create in the public schema', NOT has_schema_privilege('factory_api_app', 'public', 'CREATE'));
  PERFORM dbtest.expect_true('factory_api_app may not create in the database', NOT has_database_privilege('factory_api_app', current_database(), 'CREATE'));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. Table-level grants equal the list, both ways. The only column-level grants are the ones of `repositories`
--    (migration 2026-11-02-002400), listed after this table.

CREATE TEMP TABLE expected_api_grants (tbl text, privilege text);
INSERT INTO expected_api_grants VALUES
  -- What the transitions of a new job read (the status machine trigger) and the start-up schema check.
  ('state_machine_states', 'SELECT'), ('state_machine_transitions', 'SELECT'), ('state_machine_edges', 'SELECT'),
  ('__diesel_schema_migrations', 'SELECT'),
  -- Read: who is calling, which repository, what the job did so far.
  ('tenants', 'SELECT'), ('repositories', 'SELECT'), ('principals', 'SELECT'),
  ('stage_runs', 'SELECT'), ('outbox', 'SELECT'),
  -- Read, since migration 2026-10-29-002300: the evidence a person reads before a decision. The index of the
  -- stored documents, the links from a stage run to them, and the ledger entries that cite the gate reports.
  ('artifacts', 'SELECT'), ('stage_run_artifacts', 'SELECT'), ('ledger_entries', 'SELECT'),
  -- Read and write: the four tables the API writes.
  ('jobs', 'SELECT'), ('jobs', 'INSERT'),
  ('original_requests', 'SELECT'), ('original_requests', 'INSERT'),
  ('audit_events', 'SELECT'), ('audit_events', 'INSERT'),
  ('webhook_deliveries', 'SELECT'), ('webhook_deliveries', 'INSERT');

-- Since migration 2026-11-02-002400. A repository is registered with six columns and nothing else, so it always
-- starts disabled, at level L0, with no protection result and no bypass attestation. After that the API changes
-- the enabled flag and the project map (the commit and the person who attested it; the database stamps the time),
-- and the version, which every update of an aggregate raises by one. It cannot change the name, the installation,
-- the default branch, the autonomy ceiling, the protection result or the bypass attestation.
CREATE TEMP TABLE expected_api_column_grants (tbl text, col text, privilege text);
INSERT INTO expected_api_column_grants VALUES
  ('repositories', 'tenant_id', 'INSERT'), ('repositories', 'id', 'INSERT'),
  ('repositories', 'github_installation_id', 'INSERT'), ('repositories', 'github_repository_id', 'INSERT'),
  ('repositories', 'full_name', 'INSERT'), ('repositories', 'default_branch', 'INSERT'),
  ('repositories', 'enabled', 'UPDATE'), ('repositories', 'project_map_commit', 'UPDATE'),
  ('repositories', 'project_map_attested_by_principal_id', 'UPDATE'), ('repositories', 'version', 'UPDATE');

DO $$
DECLARE
  extra text;
  missing text;
BEGIN
  SELECT string_agg(c.relname || ':' || a.privilege_type, ', ' ORDER BY c.relname, a.privilege_type) INTO extra
    FROM pg_class c, aclexplode(c.relacl) a
   WHERE c.relnamespace = 'public'::regnamespace AND a.grantee = 'factory_api_app'::regrole
     AND NOT EXISTS (SELECT 1 FROM expected_api_grants e WHERE e.tbl = c.relname AND e.privilege = a.privilege_type);
  PERFORM dbtest.expect_eq('factory_api_app holds no table privilege beyond the expected list', coalesce(extra, ''), '');

  SELECT string_agg(e.tbl || ':' || e.privilege, ', ' ORDER BY e.tbl, e.privilege) INTO missing
    FROM expected_api_grants e
   WHERE NOT EXISTS (SELECT 1 FROM pg_class c, aclexplode(c.relacl) a
                      WHERE c.relnamespace = 'public'::regnamespace AND c.relname = e.tbl
                        AND a.grantee = 'factory_api_app'::regrole AND a.privilege_type = e.privilege);
  PERFORM dbtest.expect_eq('factory_api_app holds every table privilege on the expected list', coalesce(missing, ''), '');

  SELECT string_agg(c.relname || '.' || att.attname || ':' || a.privilege_type, ', ' ORDER BY c.relname, att.attname) INTO extra
    FROM pg_attribute att
    JOIN pg_class c ON c.oid = att.attrelid AND c.relnamespace = 'public'::regnamespace, aclexplode(att.attacl) a
   WHERE a.grantee = 'factory_api_app'::regrole;
  PERFORM dbtest.expect_eq('factory_api_app holds no column privilege outside the expected list (repositories only)',
    coalesce((SELECT string_agg(g, ', ' ORDER BY g) FROM (
      SELECT c.relname || '.' || att.attname || ':' || a.privilege_type AS g
        FROM pg_attribute att
        JOIN pg_class c ON c.oid = att.attrelid AND c.relnamespace = 'public'::regnamespace, aclexplode(att.attacl) a
       WHERE a.grantee = 'factory_api_app'::regrole
         AND NOT EXISTS (SELECT 1 FROM expected_api_column_grants e
                          WHERE e.tbl = c.relname AND e.col = att.attname AND e.privilege = a.privilege_type)) x), ''), '');
  PERFORM dbtest.expect_eq('factory_api_app holds every column privilege on the expected list',
    coalesce((SELECT string_agg(e.tbl || '.' || e.col || ':' || e.privilege, ', ' ORDER BY e.tbl, e.col, e.privilege)
                FROM expected_api_column_grants e
               WHERE NOT EXISTS (SELECT 1 FROM pg_attribute att
                                  JOIN pg_class c ON c.oid = att.attrelid AND c.relnamespace = 'public'::regnamespace, aclexplode(att.attacl) a
                                 WHERE c.relname = e.tbl AND att.attname = e.col AND a.grantee = 'factory_api_app'::regrole
                                   AND a.privilege_type = e.privilege)), ''), '');

  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO extra
    FROM pg_class c
   WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'v', 'p', 'S')
     AND c.relname <> 'repositories'
     AND (has_any_column_privilege('factory_api_app', c.oid, 'UPDATE')
          OR has_table_privilege('factory_api_app', c.oid, 'DELETE')
          OR has_table_privilege('factory_api_app', c.oid, 'TRUNCATE')
          OR has_table_privilege('factory_api_app', c.oid, 'REFERENCES')
          OR has_table_privilege('factory_api_app', c.oid, 'TRIGGER'));
  PERFORM dbtest.expect_eq('factory_api_app can neither UPDATE, DELETE, TRUNCATE, REFERENCE nor TRIGGER anything but the columns of repositories', coalesce(extra, ''), '');
  PERFORM dbtest.expect_eq('factory_api_app cannot DELETE, TRUNCATE, REFERENCE or TRIGGER on repositories either',
    (has_table_privilege('factory_api_app', 'repositories', 'DELETE') OR has_table_privilege('factory_api_app', 'repositories', 'TRUNCATE')
     OR has_table_privilege('factory_api_app', 'repositories', 'REFERENCES') OR has_table_privilege('factory_api_app', 'repositories', 'TRIGGER')), false);

  -- The tables the review listed, one by one, so the failure names the table. `repositories` was the thirteenth;
  -- it now has column grants, and its table-level INSERT is still refused (the six columns are the only way in).
  SELECT string_agg(t, ', ' ORDER BY t) INTO extra
    FROM unnest(ARRAY['api_tokens', 'principals', 'approvals', 'ledger_entries', 'outbox', 'inbox', 'stage_runs', 'attempts',
                      'task_nodes', 'task_node_dependencies', 'artifacts', 'stage_run_artifacts', 'repositories']) t
   WHERE has_table_privilege('factory_api_app', t, 'INSERT');
  PERFORM dbtest.expect_eq('factory_api_app holds no table-level INSERT on any of the 13 tables the review found', coalesce(extra, ''), '');

  SELECT string_agg(t, ', ' ORDER BY t) INTO extra
    FROM unnest(ARRAY['api_tokens', 'active_api_tokens', 'approvals', 'ledger_current_claims',
                      'ledger_assurance_levels', 'inbox', 'attempts', 'task_nodes', 'task_node_dependencies']) t
   WHERE has_table_privilege('factory_api_app', t, 'SELECT');
  PERFORM dbtest.expect_eq('factory_api_app cannot read the token, approval, claim, inbox or work tables', coalesce(extra, ''), '');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. Nobody else: PUBLIC holds no privilege on any table, view or sequence, and no column.

DO $$
DECLARE
  offenders text;
BEGIN
  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO offenders
    FROM pg_class c, aclexplode(c.relacl) a
   WHERE c.relnamespace = 'public'::regnamespace AND a.grantee = 0;
  PERFORM dbtest.expect_eq('PUBLIC holds no privilege on any table, view or sequence', coalesce(offenders, ''), '');

  SELECT string_agg(c.relname || '.' || att.attname, ', ' ORDER BY c.relname, att.attname) INTO offenders
    FROM pg_attribute att
    JOIN pg_class c ON c.oid = att.attrelid AND c.relnamespace = 'public'::regnamespace, aclexplode(att.attacl) a
   WHERE a.grantee = 0;
  PERFORM dbtest.expect_eq('PUBLIC holds no column privilege', coalesce(offenders, ''), '');

  -- The two lookups are for factory_resolver. The narrow group alone must not run them.
  PERFORM dbtest.expect_true('factory_api_app alone cannot run resolve_token (that is factory_resolver)',
    NOT has_function_privilege('factory_api_app', 'resolve_token(bytea, text)', 'EXECUTE'));
  PERFORM dbtest.expect_true('factory_api_app alone cannot run resolve_installation (that is factory_resolver)',
    NOT has_function_privilege('factory_api_app', 'resolve_installation(bigint, bigint)', 'EXECUTE'));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. A login of the API: factory_api_app and factory_resolver, and nothing else. Checked as the catalog
--    answers for that login, so inheritance is honoured the way a real session sees it. Rolled back.

BEGIN;
CREATE ROLE api_privileges_login LOGIN IN ROLE factory_api_app, factory_resolver;
DO $$
DECLARE
  extra text;
BEGIN
  PERFORM dbtest.expect_true('the API login can run both lookups',
    has_function_privilege('api_privileges_login', 'resolve_token(bytea, text)', 'EXECUTE')
    AND has_function_privilege('api_privileges_login', 'resolve_installation(bigint, bigint)', 'EXECUTE'));
  SELECT string_agg(c.relname || ':' || p.priv, ', ' ORDER BY c.relname, p.priv) INTO extra
    FROM pg_class c
    CROSS JOIN (VALUES ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE')) p(priv)
   WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
     AND has_table_privilege('api_privileges_login', c.oid, p.priv)
     AND NOT (p.priv = 'INSERT' AND c.relname IN ('jobs', 'original_requests', 'audit_events', 'webhook_deliveries'));
  PERFORM dbtest.expect_eq('the API login may write the four tables of the API and nothing else', coalesce(extra, ''), '');
  PERFORM dbtest.expect_true('the API login may write columns of repositories, and only by column grants',
    has_column_privilege('api_privileges_login', 'repositories', 'enabled', 'UPDATE')
    AND has_column_privilege('api_privileges_login', 'repositories', 'project_map_commit', 'UPDATE')
    AND NOT has_column_privilege('api_privileges_login', 'repositories', 'autonomy_ceiling', 'UPDATE')
    AND NOT has_column_privilege('api_privileges_login', 'repositories', 'protection_preflight_passed', 'UPDATE')
    AND NOT has_column_privilege('api_privileges_login', 'repositories', 'default_branch', 'UPDATE')
    AND NOT has_column_privilege('api_privileges_login', 'repositories', 'bypass_attested_by_principal_id', 'UPDATE')
    AND NOT has_column_privilege('api_privileges_login', 'repositories', 'autonomy_ceiling', 'INSERT')
    AND NOT has_column_privilege('api_privileges_login', 'repositories', 'enabled', 'INSERT'));
  PERFORM dbtest.expect_true('the API login is not a member of factory_app, factory_system or factory_lookup',
    NOT pg_has_role('api_privileges_login', 'factory_app', 'MEMBER')
    AND NOT pg_has_role('api_privileges_login', 'factory_system', 'MEMBER')
    AND NOT pg_has_role('api_privileges_login', 'factory_lookup', 'MEMBER'));
END
$$;
ROLLBACK;

-- ---------------------------------------------------------------------------------------------
-- 5. What the group does with the rows of a tenant: row-level security applies to it as it does to
--    factory_app, and the privileges above decide the rest. Two tenants, as the owner.

SELECT dbtest.mk_tenant(1), dbtest.mk_tenant(2);
SELECT dbtest.mk_job(1, 1), dbtest.mk_job(2, 1);

DO $$
DECLARE
  j uuid := dbtest.u(1550);
  audit_row text := format($q$INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason,
                       policy_hash, correlation_id)
                       VALUES (%L, %L, 'human', 'p1', 'job.submitted', 'job x', 'record', 'The job was accepted through the API.',
                       %L, %L)$q$, dbtest.u(1), dbtest.u(1560), dbtest.sha('policy'), dbtest.u(1561));
BEGIN
  -- What the API does for a tenant works.
  PERFORM dbtest.expect_eq('the group can read the jobs of the named tenant only',
    dbtest.run_as('SELECT 1 FROM jobs', 'factory_api_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the group can insert a job for the named tenant',
    dbtest.run_as(format($q$INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level,
        pipeline_scope, correlation_id, idempotency_key)
        VALUES (%L, %L, %L, %L, 'production', 'L1', ARRAY['INTAKE'], %L, 'k1')$q$,
        dbtest.u(1), j, dbtest.u(1001), dbtest.u(1002), dbtest.u(1551)), 'factory_api_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the group can insert an audit event for the named tenant',
    dbtest.run_as(audit_row, 'factory_api_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the group can insert a webhook delivery for the named tenant',
    dbtest.run_as(format($q$INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, github_installation_id, body_sha256)
        VALUES (%L, %L, 'delivery-x', 'issues', 9001, %L)$q$, dbtest.u(1), dbtest.u(1570), dbtest.sha('body-x')), 'factory_api_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the group can insert the original request of a job of the named tenant',
    dbtest.run_as(format($q$INSERT INTO original_requests (tenant_id, id, job_id, revision, source, request_text, content_sha256)
        VALUES (%L, %L, %L, 2, 'api', 'more', %L)$q$, dbtest.u(1), dbtest.u(1580), dbtest.u(1101),
        'sha256:' || encode(sha256(convert_to('more', 'UTF8')), 'hex')), 'factory_api_app', 1), 'rows=1');

  -- What it must not do: another tenant's rows, even by naming the wrong tenant in the row.
  PERFORM dbtest.expect_true('the group cannot insert an audit event for another tenant than the one it named',
    dbtest.run_as(replace(audit_row, dbtest.u(1)::text, dbtest.u(2)::text), 'factory_api_app', 1) LIKE 'ERR:42501:%');
  PERFORM dbtest.expect_eq('with no tenant named the group sees no job',
    dbtest.run_as('SELECT 1 FROM jobs', 'factory_api_app', 0), 'rows=0');
END
$$;

-- The token mint of API-3b, row by row: each is refused by the privilege, before row-level security is asked.
DO $$
DECLARE
  t record;
BEGIN
  PERFORM dbtest.expect_true('the group cannot insert a token (the end-to-end proof of API-3b)',
    dbtest.run_as(format($q$INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, expires_at)
        VALUES (%L, %L, %L, sha256(convert_to('x', 'UTF8')), 'factory-api', now() + interval '1 day')$q$,
        dbtest.u(1), dbtest.u(1990), dbtest.u(1002)), 'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table api_tokens');
  PERFORM dbtest.expect_true('the group cannot insert a principal',
    dbtest.run_as(format($q$INSERT INTO principals (tenant_id, id, kind, github_user_id, login) VALUES (%L, %L, 'human', 99, 'rogue')$q$,
        dbtest.u(1), dbtest.u(1991)), 'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table principals');
  PERFORM dbtest.expect_true('the group cannot insert an outbox event',
    dbtest.run_as(format($q$INSERT INTO outbox (tenant_id, event_id, event_type, job_id, aggregate_type, aggregate_id, aggregate_version,
        transition_id, correlation_id, occurred_at, producer, payload)
        VALUES (%L, %L, 'job.admitted', %L, 'job', %L, 2, 'J01', %L, now(), 'workflow.engine', '{}')$q$,
        dbtest.u(1), dbtest.u(1992), dbtest.u(1101), dbtest.u(1101), dbtest.u(1501)), 'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table outbox');
  FOR t IN SELECT x AS tbl FROM unnest(ARRAY['api_tokens', 'approvals', 'inbox', 'attempts', 'task_nodes']) x LOOP
    PERFORM dbtest.expect_true('the group cannot read ' || t.tbl,
      dbtest.run_as('SELECT 1 FROM ' || t.tbl, 'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table ' || t.tbl);
  END LOOP;
  PERFORM dbtest.expect_true('the group cannot update a job',
    dbtest.run_as(format($q$UPDATE jobs SET status = 'CANCELLED' WHERE id = %L$q$, dbtest.u(1101)), 'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table jobs');
  PERFORM dbtest.expect_true('the group cannot revoke a token (update api_tokens)',
    dbtest.run_as('UPDATE api_tokens SET revoked_at = now()', 'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table api_tokens');
  PERFORM dbtest.expect_true('the group cannot delete from jobs',
    dbtest.run_as('DELETE FROM jobs', 'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table jobs');
END
$$;

-- The evidence a person reads (migration 2026-10-29-002300): the three tables are read through row-level
-- security like the others, and are not written. Two tenants, as the owner.
SELECT dbtest.mk_tenant(3), dbtest.mk_tenant(4);

DO $$
DECLARE
  sha text := dbtest.sha('a document');
BEGIN
  INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend)
    VALUES (dbtest.u(3), sha, 10, 'text/plain', 'local-fs'), (dbtest.u(4), sha, 10, 'text/plain', 'local-fs');
  PERFORM dbtest.expect_eq('the group reads the artifact index of the tenant it named',
    dbtest.run_as('SELECT 1 FROM artifacts', 'factory_api_app', 3), 'rows=1');
  PERFORM dbtest.expect_eq('the group sees no artifact index row of any tenant when none is named',
    dbtest.run_as('SELECT 1 FROM artifacts', 'factory_api_app', 0), 'rows=0');
  PERFORM dbtest.expect_eq('the group reads no stage run link of another tenant',
    dbtest.run_as('SELECT 1 FROM stage_run_artifacts', 'factory_api_app', 3), 'rows=0');
  PERFORM dbtest.expect_eq('the group sees no ledger entry when no tenant is named',
    dbtest.run_as('SELECT 1 FROM ledger_entries', 'factory_api_app', 0), 'rows=0');
  PERFORM dbtest.expect_true('the group cannot insert an artifact index row',
    dbtest.run_as(format($q$INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend) VALUES (%L, %L, 1, 'text/plain', 'local-fs')$q$,
        dbtest.u(3), dbtest.sha('another')), 'factory_api_app', 3) LIKE 'ERR:42501:permission denied for table artifacts');
  PERFORM dbtest.expect_true('the group cannot update an artifact index row',
    dbtest.run_as('UPDATE artifacts SET size_bytes = 1', 'factory_api_app', 3) LIKE 'ERR:42501:permission denied for table artifacts');
  PERFORM dbtest.expect_true('the group cannot delete a ledger entry',
    dbtest.run_as('DELETE FROM ledger_entries', 'factory_api_app', 3) LIKE 'ERR:42501:permission denied for table ledger_entries');
  PERFORM dbtest.expect_true('the group cannot insert a ledger entry',
    dbtest.run_as(format($q$INSERT INTO ledger_entries (tenant_id, job_id, sequence) VALUES (%L, %L, 1)$q$,
        dbtest.u(3), dbtest.u(1101)), 'factory_api_app', 3) LIKE 'ERR:42501:permission denied for table ledger_entries');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 6. What the group may write to the audit log (RR-8 and RR-21 of
--    docs/reviews/authority-api-supply-chain-security-rereview.md; migrations 2026-10-29-002100 and
--    2026-10-29-002200, which adds decision.stage_requested).
--
--    The worker reads the audit log to find the requests of people, and to find the records that end a
--    request. The API login may INSERT into the log (section 2), and a row is a row: until the trigger
--    audit_events_api_actions, that login could write a record in the name of the worker (a
--    decision.rejected that ends a signed request unseen) or a queue of junk. Now the login writes the
--    actions the API writes, and no other.

CREATE FUNCTION dbtest.api_audit_stmt(p_actor_type text, p_action text) RETURNS text LANGUAGE sql AS $$
  SELECT format($q$INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason,
                       policy_hash, correlation_id)
                       VALUES (%L, %L, %L, 'p1', %L, 'subject', 'record', 'because', %L, %L)$q$,
                dbtest.u(1), gen_random_uuid(), p_actor_type, p_action, dbtest.sha('policy'), gen_random_uuid())
$$;

DO $$
DECLARE
  allowed text[] := ARRAY[
    'decision.requested', 'decision.dependency_requested', 'decision.stage_requested', 'decision.denied',
    'decision.denied_summary', 'decision.denied_suppressed', 'job.submitted', 'job.received_from_webhook', 'webhook.accepted',
    'webhook.duplicate_delivery', 'webhook.rejected', 'webhook.unbound', 'webhook.audit_dropped',
    'webhook_accepted_or_rejected.granted', 'webhook_accepted_or_rejected.denied',
    -- Since migration 2026-11-02-002400: what the API writes when a person changes a repository.
    'repository.registered', 'repository.map_attested', 'repository.enabled', 'repository.disabled'];
  refused text[] := ARRAY[
    -- What the worker writes: a marker that ends a request, and the record that a marker was ignored.
    'decision.applied', 'decision.rejected', 'decision.marker_ignored',
    -- What the engine, the stages and the preflight write.
    'approval.recorded', 'job.admitted', 'repository.protection_preflight', 'gate.result',
    -- Near misses: the list is exact, not a prefix, a pattern or a case-insensitive match.
    'decision.requested2', 'decision.request', 'decision', 'job.submitted.extra', 'webhook.accepted_by_worker',
    'webhook_accepted_or_rejected', 'webhook_accepted_or_rejected.noted',
    'decision.dependency_requested_', 'decision.stage_requested_', 'decision.stage_request', 'x',
    'repository', 'repository.register', 'repository.enable', 'repository.registered_by_worker', 'repository.map_attested.extra'];
  a text;
  msg text;
BEGIN
  FOREACH a IN ARRAY allowed LOOP
    PERFORM dbtest.expect_eq('the group may write a ' || a || ' record as a person',
      dbtest.run_as(dbtest.api_audit_stmt('human', a), 'factory_api_app', 1), 'rows=1');
  END LOOP;
  FOREACH a IN ARRAY refused LOOP
    msg := dbtest.run_as(dbtest.api_audit_stmt('human', a), 'factory_api_app', 1);
    PERFORM dbtest.expect_true('the group cannot write a ' || a || ' record',
      msg LIKE 'ERR:42501:the API login may not write an audit record with this action or this actor%', msg);
  END LOOP;

  -- The actor is not limited: what the hook reads is decided by the action and by the words in the row (a
  -- request needs a person's id and the API's word, a marker the worker's word), never by the actor type.
  PERFORM dbtest.expect_eq('the group may write an anonymous webhook record',
    dbtest.run_as(dbtest.api_audit_stmt('anonymous', 'webhook.rejected'), 'factory_api_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the group may write a platform event of the receiver as a component of the system',
    dbtest.run_as(dbtest.api_audit_stmt('system', 'webhook_accepted_or_rejected.denied'), 'factory_api_app', 1), 'rows=1');
  msg := dbtest.run_as(dbtest.api_audit_stmt('system', 'decision.rejected'), 'factory_api_app', 1);
  PERFORM dbtest.expect_true('the group cannot write the worker''s marker even as a component of the system',
    msg LIKE 'ERR:42501:the API login may not write an audit record with this action or this actor%', msg);

  -- Everybody else is as before: the worker's group writes its markers, as a component of the system.
  PERFORM dbtest.expect_eq('the worker group may still write a decision.applied record as the system',
    dbtest.run_as(dbtest.api_audit_stmt('system', 'decision.applied'), 'factory_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the worker group may still write a decision.rejected record as the system',
    dbtest.run_as(dbtest.api_audit_stmt('system', 'decision.rejected'), 'factory_app', 1), 'rows=1');
END
$$;

-- A login that is a member of the group is held to the same list as the group (it is the login that
-- connects, not the group), also when it names the tenant by hand as the API does.
BEGIN;
CREATE ROLE api_actions_login LOGIN IN ROLE factory_api_app, factory_resolver;
DO $$
DECLARE
  msg text;
BEGIN
  PERFORM dbtest.expect_eq('a login of the group may write a decision.requested record',
    dbtest.run_as(dbtest.api_audit_stmt('human', 'decision.requested'), 'api_actions_login', 1, NULL, false, dbtest.u(1)::text), 'rows=1');
  msg := dbtest.run_as(dbtest.api_audit_stmt('system', 'decision.rejected'), 'api_actions_login', 1, NULL, false, dbtest.u(1)::text);
  PERFORM dbtest.expect_true('a login of the group cannot write a record in the name of the worker',
    msg LIKE 'ERR:42501:the API login may not write an audit record with this action or this actor%', msg);
END
$$;
ROLLBACK;
