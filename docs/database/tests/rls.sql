-- Suite: rls
-- Proves ADR 0012, the database part of NT-TEN-01: row-level security on every tenant-owned table, a
-- separate role for the system scope, and two narrow SECURITY DEFINER lookups for the work that happens
-- before a tenant is known. The structure is read from the catalog, so a new table without a policy
-- fails here. The checks that need real logins and separate connections (a reused connection, a
-- poisoned pool, concurrent claimers) run from scripts/db-test.sh after this file.
--
-- How a check is made. Fixtures are written by the table owner (a superuser in the test cluster, which
-- bypasses row-level security by its nature, so it can arrange the data). Every attempt on that data is
-- then made as a group role (SET LOCAL ROLE) inside a subtransaction that is always rolled back, with
-- the tenant setting that Store::begin would make. The group roles stand for the logins of the
-- deployment, which are members of them.

-- ---------------------------------------------------------------------------------------------
-- 1. The roles.

-- What is wrong with a role that is supposed to be an unprivileged group. An empty string means nothing.
CREATE FUNCTION dbtest.group_role_problems(p_role text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  r pg_roles%ROWTYPE;
  problems text := '';
  n bigint;
BEGIN
  SELECT * INTO r FROM pg_roles WHERE rolname = p_role;
  IF NOT FOUND THEN
    RETURN p_role || ' does not exist; ';
  END IF;
  IF r.rolcanlogin THEN problems := problems || 'can log in; '; END IF;
  IF r.rolsuper THEN problems := problems || 'is a superuser; '; END IF;
  IF r.rolbypassrls THEN problems := problems || 'has BYPASSRLS; '; END IF;
  IF r.rolcreaterole THEN problems := problems || 'can create roles; '; END IF;
  IF r.rolcreatedb THEN problems := problems || 'can create databases; '; END IF;
  IF r.rolreplication THEN problems := problems || 'can replicate; '; END IF;
  SELECT count(*) INTO n FROM pg_class WHERE relowner = r.oid;
  IF n > 0 THEN problems := problems || format('owns %s relations (tables, views, sequences or indexes); ', n); END IF;
  SELECT count(*) INTO n FROM pg_namespace WHERE nspowner = r.oid;
  IF n > 0 THEN problems := problems || format('owns %s schemas; ', n); END IF;
  SELECT count(*) INTO n FROM pg_database WHERE datdba = r.oid;
  IF n > 0 THEN problems := problems || format('owns %s databases; ', n); END IF;
  IF has_schema_privilege(p_role, 'public', 'CREATE') THEN problems := problems || 'can create objects in the public schema; '; END IF;
  IF has_database_privilege(p_role, current_database(), 'CREATE') THEN problems := problems || 'can create schemas in the database; '; END IF;
  SELECT count(*) INTO n FROM pg_auth_members WHERE member = r.oid;
  IF n > 0 THEN problems := problems || format('is a member of %s roles; ', n); END IF;
  RETURN problems;
END
$$;

-- Every member, direct or through other roles, of the four groups. Superusers are not listed as members
-- by this walk: the walk follows pg_auth_members only, because PostgreSQL treats a superuser as a member
-- of everything and that would hide the grants that were really made.
CREATE FUNCTION dbtest.group_members() RETURNS TABLE (grp text, member text, can_login boolean, is_super boolean, bypass_rls boolean)
LANGUAGE sql AS $$
  WITH RECURSIVE walk(grp_oid, member_oid) AS (
    SELECT g.oid, a.member
      FROM pg_roles g JOIN pg_auth_members a ON a.roleid = g.oid
     WHERE g.rolname IN ('factory_app', 'factory_system', 'factory_lookup', 'factory_resolver')
    UNION
    SELECT w.grp_oid, a.member FROM walk w JOIN pg_auth_members a ON a.roleid = w.member_oid
  )
  SELECT g.rolname::text, m.rolname::text, m.rolcanlogin, m.rolsuper, m.rolbypassrls
    FROM walk w JOIN pg_roles g ON g.oid = w.grp_oid JOIN pg_roles m ON m.oid = w.member_oid
$$;

-- Pairs of groups that no role may belong to together. Permissive policies are combined with OR, so a
-- login in both factory_app and factory_system would see every row. factory_resolver is for the login
-- that authenticates requests and must not also be the engine's system login. factory_lookup owns the
-- two lookup functions and nobody may be it.
CREATE FUNCTION dbtest.membership_conflicts() RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(DISTINCT a.member || ' is a member of both ' || least(a.grp, b.grp) || ' and ' || greatest(a.grp, b.grp), '; '), '')
       || coalesce((SELECT '; ' || string_agg(DISTINCT member || ' is a member of factory_lookup', '; ') FROM dbtest.group_members() WHERE grp = 'factory_lookup' AND NOT is_super), '')
    FROM dbtest.group_members() a
    JOIN dbtest.group_members() b ON a.member = b.member AND a.grp < b.grp
   WHERE a.grp IN ('factory_app', 'factory_system', 'factory_resolver') AND b.grp IN ('factory_app', 'factory_system', 'factory_resolver')
     AND (a.grp, b.grp) <> ('factory_app', 'factory_resolver')
$$;

DO $$
DECLARE
  g text;
BEGIN
  FOREACH g IN ARRAY ARRAY['factory_app', 'factory_system', 'factory_lookup', 'factory_resolver'] LOOP
    PERFORM dbtest.expect_eq(g || ' is a NOLOGIN group with no superuser, BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION, owns nothing and cannot create in public',
      dbtest.group_role_problems(g), '');
  END LOOP;
  PERFORM dbtest.expect_eq('no login belongs to both factory_app and factory_system, to factory_system and factory_resolver, or to factory_lookup',
    dbtest.membership_conflicts(), '');
  PERFORM dbtest.expect_eq('no member of any group is a superuser or has BYPASSRLS',
    (SELECT coalesce(string_agg(grp || ':' || member, ', '), '') FROM dbtest.group_members() WHERE is_super OR bypass_rls), '');
END
$$;

-- Control: the check is not vacuous. A login in two incompatible groups is reported, and so is a member of
-- the lookup owner and a member with BYPASSRLS. Everything is rolled back.
DO $$
DECLARE
  seen text;
BEGIN
  BEGIN
    CREATE ROLE dbtest_both LOGIN IN ROLE factory_app, factory_system;
    seen := dbtest.membership_conflicts();
    RAISE EXCEPTION 'rollback' USING ERRCODE = 'XX998';
  EXCEPTION WHEN SQLSTATE 'XX998' THEN NULL;
  END;
  PERFORM dbtest.expect_true('control: a login in both factory_app and factory_system is reported', seen LIKE '%dbtest_both is a member of both factory_app and factory_system%', seen);

  BEGIN
    CREATE ROLE dbtest_lookup_member LOGIN IN ROLE factory_lookup;
    seen := dbtest.membership_conflicts();
    RAISE EXCEPTION 'rollback' USING ERRCODE = 'XX998';
  EXCEPTION WHEN SQLSTATE 'XX998' THEN NULL;
  END;
  PERFORM dbtest.expect_true('control: a login that is a member of factory_lookup is reported', seen LIKE '%dbtest_lookup_member is a member of factory_lookup%', seen);

  BEGIN
    CREATE ROLE dbtest_bypasser LOGIN BYPASSRLS IN ROLE factory_app;
    seen := (SELECT coalesce(string_agg(grp || ':' || member, ', '), '') FROM dbtest.group_members() WHERE is_super OR bypass_rls);
    RAISE EXCEPTION 'rollback' USING ERRCODE = 'XX998';
  EXCEPTION WHEN SQLSTATE 'XX998' THEN NULL;
  END;
  PERFORM dbtest.expect_eq('control: a group member with BYPASSRLS is reported', seen, 'factory_app:dbtest_bypasser');

  BEGIN
    ALTER ROLE factory_system BYPASSRLS;
    seen := dbtest.group_role_problems('factory_system');
    RAISE EXCEPTION 'rollback' USING ERRCODE = 'XX998';
  EXCEPTION WHEN SQLSTATE 'XX998' THEN NULL;
  END;
  PERFORM dbtest.expect_true('control: BYPASSRLS on a group role is reported', seen LIKE '%has BYPASSRLS%', seen);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. Every tenant-owned table, found from the catalog.

-- Tables with a tenant_id column are the tenant-owned tables (the same rule as the tenancy suite). A function
-- and not a table, so that a control can create a table and have it found.
CREATE FUNCTION dbtest.tenant_tables() RETURNS SETOF text LANGUAGE sql AS $$
  SELECT c.relname::text
    FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
   WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
   ORDER BY 1
$$;

-- One row in every tenant-owned table for tenant t, written by the owner. Tenant 1 and tenant 2 each get
-- a full set, so a check can compare what a session sees with what exists. A new tenant-owned table
-- without a line here makes dbtest.isolation_problems report "no fixture rows" and the suite fails.
CREATE FUNCTION dbtest.mk_everything(t int) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  tn uuid := dbtest.u(t);
  job uuid := dbtest.u(t * 1000 + 101);
  run uuid := dbtest.u(t * 1000 + 201);
  attempt uuid := dbtest.u(t * 1000 + 301);
  node_a uuid := dbtest.u(t * 1000 + 401);
  node_b uuid := dbtest.u(t * 1000 + 402);
  plan_hash text := dbtest.sha('plan-' || t);
  delivery uuid := dbtest.u(t * 1000 + 701);
BEGIN
  PERFORM dbtest.mk_tenant(t);                       -- tenants, repositories, two principals
  PERFORM dbtest.mk_job(t, 1);
  PERFORM dbtest.set_status('jobs', t, job, 'ACTIVE');   -- job version 2, so an event for version 2 is legal
  PERFORM dbtest.mk_stage_run(t, 1, 1);
  PERFORM dbtest.set_status('stage_runs', t, run, 'READY');
  PERFORM dbtest.set_status('stage_runs', t, run, 'RUNNING', ', lease_epoch = lease_epoch + 1');
  INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend)
    VALUES (tn, plan_hash, 10, 'text/plain', 'local-fs'), (tn, dbtest.sha('input-' || t), 10, 'text/plain', 'local-fs');
  INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, github_installation_id, body_sha256)
    VALUES (tn, delivery, 'delivery-' || t, 'issues', 9000 + t, dbtest.sha('body-' || t));
  INSERT INTO original_requests (tenant_id, id, job_id, revision, source, request_text, content_sha256)
    VALUES (tn, dbtest.u(t * 1000 + 801), job, 1, 'api', 'text of tenant ' || t,
            'sha256:' || encode(sha256(convert_to('text of tenant ' || t, 'UTF8')), 'hex'));
  INSERT INTO stage_run_artifacts (tenant_id, job_id, stage_run_id, direction, role, content_sha256)
    VALUES (tn, job, run, 'input', 'spec', dbtest.sha('input-' || t));
  INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
    VALUES (tn, attempt, job, run, 1, 'worker-' || t, 1, now() + interval '30 seconds', now() + interval '1 hour');
  INSERT INTO task_nodes (tenant_id, id, job_id, stage_run_id, task_key, plan_sha256)
    VALUES (tn, node_a, job, run, 'task-a', plan_hash), (tn, node_b, job, run, 'task-b', plan_hash);
  INSERT INTO task_node_dependencies (tenant_id, stage_run_id, task_node_id, depends_on_task_node_id)
    VALUES (tn, run, node_b, node_a);
  PERFORM dbtest.append_entry(t, job, run, 1);       -- ledger_entries
  PERFORM dbtest.audit(t, 1);                        -- audit_events
  INSERT INTO outbox (tenant_id, event_id, event_type, job_id, aggregate_type, aggregate_id, aggregate_version, transition_id,
                      correlation_id, occurred_at, producer, payload)
    VALUES (tn, dbtest.u(t * 1000 + 901), 'job.admitted', job, 'job', job, 2, 'J01', dbtest.u(t * 1000 + 501), now(), 'workflow.engine', '{}');
  INSERT INTO inbox (tenant_id, consumer, event_id) VALUES (tn, 'dashboard', dbtest.u(t * 1000 + 901));
  INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, expires_at)
    VALUES (tn, dbtest.u(t * 1000 + 951), dbtest.u(t * 1000 + 2), sha256(convert_to('token-' || t, 'UTF8')), 'factory-api', now() + interval '1 day');
  INSERT INTO approvals (tenant_id, id, job_id, stage_run_id, decision, approver_principal_id, approver_github_user_id, approver_designation,
                         allowlist_version_hash, policy_hash, reason, channel, expires_at, pr_head_sha, tree_hash, base_sha, evidence_manifest_hash, spec_version)
    VALUES (tn, dbtest.u(t * 1000 + 961), job, run, 'approve', dbtest.u(t * 1000 + 2), 7000 + t, 'approver',
            dbtest.sha('allowlist'), dbtest.sha('policy'), 'Reviewed the evidence.', 'cli', now() + interval '72 hours',
            repeat('a', 40), repeat('b', 40), repeat('c', 40), dbtest.sha('manifest'), 1);
END
$$;

SELECT dbtest.mk_everything(1);
SELECT dbtest.mk_everything(2);

-- What is wrong with the policy of one tenant-owned table. An empty string means nothing.
CREATE FUNCTION dbtest.policy_problems(p_tbl text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  c pg_class%ROWTYPE;
  p pg_policy%ROWTYPE;
  problems text := '';
  qual text;
  check_text text;
  expected text := '(tenant_id = (NULLIF(current_setting(''factory.tenant_id''::text, true), ''''::text))::uuid)';
BEGIN
  SELECT * INTO c FROM pg_class WHERE oid = ('public.' || p_tbl)::regclass;
  IF NOT c.relrowsecurity THEN problems := problems || 'row-level security is not enabled; '; END IF;
  IF NOT c.relforcerowsecurity THEN problems := problems || 'FORCE ROW LEVEL SECURITY is not set (the table owner is not bound); '; END IF;
  SELECT * INTO p FROM pg_policy WHERE polrelid = c.oid AND polname = 'tenant_isolation';
  IF NOT FOUND THEN
    RETURN problems || 'there is no policy tenant_isolation; ';
  END IF;
  IF p.polcmd <> '*' THEN problems := problems || 'the policy does not cover all commands; '; END IF;
  IF NOT p.polpermissive THEN problems := problems || 'the policy is not permissive; '; END IF;
  IF p.polroles <> ARRAY['factory_app'::regrole::oid] THEN problems := problems || 'the policy is not for factory_app alone; '; END IF;
  qual := pg_get_expr(p.polqual, p.polrelid);
  check_text := pg_get_expr(p.polwithcheck, p.polrelid);
  IF qual IS DISTINCT FROM expected THEN problems := problems || format('USING is %s, not the NULLIF form; ', qual); END IF;
  IF check_text IS DISTINCT FROM expected THEN problems := problems || format('WITH CHECK is %s, not the NULLIF form; ', check_text); END IF;
  RETURN problems;
END
$$;

-- What a tenant-1 session can do to tenant 2's rows in one table, and what a session with no tenant can
-- do, compared with what must happen. An empty string means the table is isolated.
CREATE FUNCTION dbtest.isolation_problems(p_tbl text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  problems text := '';
  mine bigint;
  theirs bigint;
  doc2 jsonb;
  col text;
  cols text;
  got text;
  copy_stmt text;
  q text := format('SELECT 1 FROM %I', p_tbl);
  grant_update text;
  grant_tenant text;
  grant_delete text := format('GRANT DELETE ON %I TO factory_app', p_tbl);
BEGIN
  EXECUTE format('SELECT count(*) FROM %I WHERE tenant_id = dbtest.u(1)', p_tbl) INTO mine;
  EXECUTE format('SELECT count(*) FROM %I WHERE tenant_id = dbtest.u(2)', p_tbl) INTO theirs;
  IF mine < 1 OR theirs < 1 THEN
    RETURN format('no fixture rows in %s (tenant 1 has %s, tenant 2 has %s); ', p_tbl, mine, theirs);
  END IF;

  -- SELECT.
  got := dbtest.run_as(q, 'factory_app', 1);
  IF got <> 'rows=' || mine THEN problems := problems || format('tenant 1 sees %s, expected only its %s rows; ', got, mine); END IF;
  got := dbtest.run_as(q || ' WHERE tenant_id = dbtest.u(2)', 'factory_app', 1);
  IF got <> 'rows=0' THEN problems := problems || format('tenant 1 asking for tenant 2 rows got %s; ', got); END IF;
  got := dbtest.run_as(q, 'factory_app', 2);
  IF got <> 'rows=' || theirs THEN problems := problems || format('tenant 2 sees %s, expected its %s rows (the fixture is not visible to its own tenant); ', got, theirs); END IF;
  got := dbtest.run_as(q, 'factory_app', 0);
  IF got <> 'rows=0' THEN problems := problems || format('a transaction with an empty tenant setting got %s, expected zero rows and no error; ', got); END IF;
  got := dbtest.run_as(q, 'factory_app', NULL, NULL, false, 'not-a-uuid');
  IF got NOT LIKE 'ERR:22P02:%' THEN problems := problems || format('a garbage tenant setting got %s, expected an error (22P02); ', got); END IF;

  -- INSERT: an exact copy of a tenant 2 row. The user triggers are off so that none answers before the
  -- policy does; the policy check also comes before the constraints. The control is tenant 2 itself,
  -- which gets past the policy and is stopped by the primary key.
  EXECUTE format('SELECT to_jsonb(x) FROM (SELECT * FROM %I WHERE tenant_id = dbtest.u(2) LIMIT 1) x', p_tbl) INTO doc2;
  doc2 := doc2 - ARRAY(SELECT a.attname::text FROM pg_attribute a WHERE a.attrelid = ('public.' || p_tbl)::regclass AND a.attnum > 0 AND a.attidentity <> '' AND NOT a.attisdropped);
  SELECT string_agg(format('%I', a.attname), ', ' ORDER BY a.attnum) INTO cols
    FROM pg_attribute a WHERE a.attrelid = ('public.' || p_tbl)::regclass AND a.attnum > 0 AND a.attidentity = '' AND NOT a.attisdropped;
  copy_stmt := format('INSERT INTO %I (%s) SELECT %s FROM jsonb_populate_record(NULL::%I, %L::jsonb)', p_tbl, cols, cols, p_tbl, doc2);
  got := dbtest.run_as(copy_stmt, 'factory_app', 1, NULL, true);
  IF got NOT LIKE 'ERR:42501:new row violates row-level security policy%' THEN problems := problems || format('tenant 1 inserting a tenant 2 row got %s; ', got); END IF;
  got := dbtest.run_as(copy_stmt, 'factory_app', 0, NULL, true);
  IF got NOT LIKE 'ERR:42501:new row violates row-level security policy%' THEN problems := problems || format('a session with no tenant inserting a row got %s; ', got); END IF;
  got := dbtest.run_as(copy_stmt, 'factory_app', 2, NULL, true);
  IF got NOT LIKE 'ERR:23505:%' THEN problems := problems || format('control: tenant 2 inserting its own row again got %s, expected the primary key to answer; ', got); END IF;

  -- UPDATE, with a temporary column grant so that the policy, not the missing grant, is what answers.
  SELECT a.attname INTO col FROM pg_attribute a
   WHERE a.attrelid = ('public.' || p_tbl)::regclass AND a.attnum > 0 AND NOT a.attisdropped AND a.attidentity = '' AND a.attname <> 'tenant_id'
   ORDER BY a.attnum LIMIT 1;
  grant_update := format('GRANT UPDATE (%I) ON %I TO factory_app', col, p_tbl);
  grant_tenant := format('GRANT UPDATE (tenant_id) ON %I TO factory_app', p_tbl);
  got := dbtest.run_as(format('UPDATE %I SET %I = %I WHERE tenant_id = dbtest.u(2)', p_tbl, col, col), 'factory_app', 1, grant_update, true);
  IF got <> 'rows=0' THEN problems := problems || format('tenant 1 updating tenant 2 rows got %s; ', got); END IF;
  got := dbtest.run_as(format('UPDATE %I SET %I = %I', p_tbl, col, col), 'factory_app', 1, grant_update, true);
  IF got <> 'rows=' || mine THEN problems := problems || format('tenant 1 updating every row it can see got %s, expected only its %s; ', got, mine); END IF;
  got := dbtest.run_as(format('UPDATE %I SET %I = %I', p_tbl, col, col), 'factory_app', 2, grant_update, true);
  IF got <> 'rows=' || theirs THEN problems := problems || format('control: tenant 2 updating its own rows got %s, expected %s; ', got, theirs); END IF;
  got := dbtest.run_as(format('UPDATE %I SET %I = %I', p_tbl, col, col), 'factory_app', 0, grant_update, true);
  IF got <> 'rows=0' THEN problems := problems || format('a session with no tenant updating got %s; ', got); END IF;
  got := dbtest.run_as(format('UPDATE %I SET tenant_id = dbtest.u(2) WHERE tenant_id = dbtest.u(1)', p_tbl), 'factory_app', 1, grant_tenant, true);
  IF got NOT LIKE 'ERR:42501:new row violates row-level security policy%' THEN problems := problems || format('tenant 1 moving its row to tenant 2 got %s; ', got); END IF;

  -- DELETE, with a temporary grant (the application role has none).
  got := dbtest.run_as(format('DELETE FROM %I WHERE tenant_id = dbtest.u(2)', p_tbl), 'factory_app', 1, grant_delete, true);
  IF got <> 'rows=0' THEN problems := problems || format('tenant 1 deleting tenant 2 rows got %s; ', got); END IF;
  got := dbtest.run_as(format('DELETE FROM %I', p_tbl), 'factory_app', 1, grant_delete, true);
  IF got <> 'rows=' || mine THEN problems := problems || format('tenant 1 deleting everything it can see got %s, expected only its %s; ', got, mine); END IF;
  got := dbtest.run_as(format('DELETE FROM %I', p_tbl), 'factory_app', 2, grant_delete, true);
  IF got <> 'rows=' || theirs THEN problems := problems || format('control: tenant 2 deleting its own rows got %s, expected %s; ', got, theirs); END IF;
  got := dbtest.run_as(format('DELETE FROM %I', p_tbl), 'factory_app', 0, grant_delete, true);
  IF got <> 'rows=0' THEN problems := problems || format('a session with no tenant deleting got %s; ', got); END IF;

  RETURN problems;
END
$$;

-- The problems of every tenant-owned table the catalog knows now, one line per table with a problem.
CREATE FUNCTION dbtest.all_table_problems() RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  t text;
  one text;
  all_problems text := '';
BEGIN
  FOR t IN SELECT * FROM dbtest.tenant_tables() LOOP
    one := dbtest.policy_problems(t) || dbtest.isolation_problems(t);
    IF one <> '' THEN
      all_problems := all_problems || format('[%s] %s', t, one);
    END IF;
  END LOOP;
  RETURN all_problems;
END
$$;

DO $$
BEGIN
  PERFORM dbtest.expect_eq('the catalog found the 17 tenant-owned tables (a new one must be added to mk_everything and to the policy migration)',
    (SELECT count(*) FROM dbtest.tenant_tables()), 17::bigint);
  PERFORM dbtest.expect_eq('all 17 tenant-owned tables are isolated: a tenant-1 session cannot read, insert, update or delete tenant 2 rows, and a session with no tenant sees nothing',
    dbtest.all_table_problems(), '');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. The checks can fail. Each break below is made inside a subtransaction, the same checks run, and the
-- break is rolled back. A suite that cannot see a broken table proves nothing.

DO $$
DECLARE
  seen text;
  m record;
BEGIN
  FOR m IN SELECT * FROM (VALUES
    ('row-level security switched off on jobs', 'ALTER TABLE jobs DISABLE ROW LEVEL SECURITY'),
    ('FORCE ROW LEVEL SECURITY removed from jobs (the owner is no longer bound)', 'ALTER TABLE jobs NO FORCE ROW LEVEL SECURITY'),
    ('the policy dropped from jobs', 'DROP POLICY tenant_isolation ON jobs'),
    ('NULLIF removed from the policy of jobs',
     'ALTER POLICY tenant_isolation ON jobs USING (tenant_id = current_setting(''factory.tenant_id'', true)::uuid) WITH CHECK (tenant_id = current_setting(''factory.tenant_id'', true)::uuid)'),
    ('the policy of jobs opened to every row', 'ALTER POLICY tenant_isolation ON jobs USING (true) WITH CHECK (true)'),
    ('the WITH CHECK of jobs opened', 'ALTER POLICY tenant_isolation ON jobs WITH CHECK (true)'),
    ('a second permissive policy that admits every row added to jobs', 'CREATE POLICY leak ON jobs FOR SELECT USING (true)'),
    ('a policy for PUBLIC instead of factory_app', 'ALTER POLICY tenant_isolation ON jobs TO PUBLIC'),
    ('BYPASSRLS granted to factory_app', 'ALTER ROLE factory_app BYPASSRLS'),
    ('a new tenant-owned table with no policy', 'CREATE TABLE public.sneaky (tenant_id uuid NOT NULL, note text)')
  ) AS v(what, ddl) LOOP
    BEGIN
      EXECUTE m.ddl;
      seen := dbtest.all_table_problems();
      RAISE EXCEPTION 'rollback' USING ERRCODE = 'XX998';
    EXCEPTION WHEN SQLSTATE 'XX998' THEN NULL;
    END;
    PERFORM dbtest.expect_true('control: ' || m.what || ' is reported', seen <> '', 'the checks found nothing wrong');
  END LOOP;
  PERFORM dbtest.expect_eq('and after the controls were rolled back every table is isolated again', dbtest.all_table_problems(), '');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. The system scope can do only what the engine's loops must (ADR 0012, section 3).
--
-- The claim, the sweep and the outbox relay look across tenants for work. They FIND work and return
-- identifiers; the transition itself is made afterwards in a tenant transaction, so every write to a
-- job, a stage run, the ledger and the outbox happens under the tenant policy. factory_system therefore
-- has: read access to the columns the finding queries use (stage_runs, jobs, attempts), the right to LOCK
-- stage runs and attempts (FOR NO KEY UPDATE SKIP LOCKED needs an UPDATE privilege and an UPDATE policy)
-- but no way to change them, and the outbox relay's two bookkeeping columns. Nothing else.

-- A stage run that is READY and claimable, an expired lease, and an unpublished event, in each tenant.
DO $$
BEGIN
  -- Tenant 1 and tenant 2 each get a second stage run that is READY.
  INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number)
    SELECT dbtest.u(t), dbtest.u(t * 1000 + 202), dbtest.u(t * 1000 + 101), 'REPOSITORY_INTELLIGENCE', 1 FROM generate_series(1, 2) AS t;
  PERFORM dbtest.set_status('stage_runs', t, dbtest.u(t * 1000 + 202), 'READY') FROM generate_series(1, 2) AS t;
  -- The attempts of the fixture are alive; expire the lease of both.
  UPDATE attempts SET lease_expires_at = now() - interval '1 minute', version = version + 1;
END
$$;

-- What factory_system holds, from the catalog, written out here so that a change to a grant is a change to
-- this file. Table-level grants, then column-level ones.
CREATE TEMP TABLE system_table_grants (tbl text, privilege text);
INSERT INTO system_table_grants VALUES ('outbox', 'SELECT'), ('__diesel_schema_migrations', 'SELECT');
CREATE TEMP TABLE system_column_grants (tbl text, col text, privilege text);
INSERT INTO system_column_grants VALUES
  ('stage_runs', 'tenant_id', 'SELECT'), ('stage_runs', 'id', 'SELECT'), ('stage_runs', 'job_id', 'SELECT'),
  ('stage_runs', 'status', 'SELECT'), ('stage_runs', 'version', 'SELECT'), ('stage_runs', 'not_before', 'SELECT'),
  ('stage_runs', 'updated_at', 'UPDATE'),
  ('jobs', 'tenant_id', 'SELECT'), ('jobs', 'id', 'SELECT'), ('jobs', 'status', 'SELECT'),
  ('attempts', 'tenant_id', 'SELECT'), ('attempts', 'id', 'SELECT'), ('attempts', 'job_id', 'SELECT'),
  ('attempts', 'stage_run_id', 'SELECT'), ('attempts', 'status', 'SELECT'), ('attempts', 'version', 'SELECT'),
  ('attempts', 'lease_epoch', 'SELECT'), ('attempts', 'lease_expires_at', 'SELECT'), ('attempts', 'deadline_at', 'SELECT'),
  ('attempts', 'teardown_deadline_at', 'SELECT'), ('attempts', 'updated_at', 'UPDATE'),
  ('outbox', 'published_at', 'UPDATE'), ('outbox', 'publish_attempts', 'UPDATE');

DO $$
DECLARE
  extra text;
  missing text;
BEGIN
  SELECT string_agg(c.relname || ':' || a.privilege_type, ', ' ORDER BY c.relname, a.privilege_type) INTO extra
    FROM pg_class c, aclexplode(c.relacl) a
   WHERE c.relnamespace = 'public'::regnamespace AND a.grantee = 'factory_system'::regrole
     AND NOT EXISTS (SELECT 1 FROM system_table_grants e WHERE e.tbl = c.relname AND e.privilege = a.privilege_type);
  PERFORM dbtest.expect_eq('factory_system holds no table privilege beyond the expected list', coalesce(extra, ''), '');
  SELECT string_agg(e.tbl || ':' || e.privilege, ', ' ORDER BY e.tbl) INTO missing
    FROM system_table_grants e
   WHERE NOT EXISTS (SELECT 1 FROM pg_class c, aclexplode(c.relacl) a
                      WHERE c.relnamespace = 'public'::regnamespace AND c.relname = e.tbl AND a.grantee = 'factory_system'::regrole AND a.privilege_type = e.privilege);
  PERFORM dbtest.expect_eq('factory_system holds every table privilege on the expected list', coalesce(missing, ''), '');

  SELECT string_agg(c.relname || '.' || att.attname || ':' || a.privilege_type, ', ' ORDER BY c.relname, att.attname) INTO extra
    FROM pg_attribute att JOIN pg_class c ON c.oid = att.attrelid AND c.relnamespace = 'public'::regnamespace, aclexplode(att.attacl) a
   WHERE a.grantee = 'factory_system'::regrole
     AND NOT EXISTS (SELECT 1 FROM system_column_grants e WHERE e.tbl = c.relname AND e.col = att.attname AND e.privilege = a.privilege_type);
  PERFORM dbtest.expect_eq('factory_system holds no column privilege beyond the expected list', coalesce(extra, ''), '');
  SELECT string_agg(e.tbl || '.' || e.col || ':' || e.privilege, ', ' ORDER BY e.tbl, e.col) INTO missing
    FROM system_column_grants e
   WHERE NOT EXISTS (SELECT 1 FROM pg_attribute att JOIN pg_class c ON c.oid = att.attrelid AND c.relnamespace = 'public'::regnamespace, aclexplode(att.attacl) a
                      WHERE c.relname = e.tbl AND att.attname = e.col AND a.grantee = 'factory_system'::regrole AND a.privilege_type = e.privilege);
  PERFORM dbtest.expect_eq('factory_system holds every column privilege on the expected list', coalesce(missing, ''), '');

  PERFORM dbtest.expect_eq('factory_system holds no INSERT, DELETE, TRUNCATE, REFERENCES or TRIGGER privilege anywhere',
    (SELECT coalesce(string_agg(c.relname || ':' || a.privilege_type, ', '), '') FROM pg_class c, aclexplode(c.relacl) a
      WHERE c.relnamespace = 'public'::regnamespace AND a.grantee = 'factory_system'::regrole
        AND a.privilege_type IN ('INSERT', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER')), '');
  PERFORM dbtest.expect_eq('factory_system holds no sequence privilege and no function privilege on the product schema',
    (SELECT count(*) FROM pg_class c, aclexplode(c.relacl) a WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'S' AND a.grantee = 'factory_system'::regrole)
    + (SELECT count(*) FROM pg_proc p, aclexplode(p.proacl) a WHERE p.pronamespace = 'public'::regnamespace AND a.grantee = 'factory_system'::regrole), 0::bigint);
END
$$;

-- What it can do.
DO $$
DECLARE
  claim text := $q$SELECT s.tenant_id, s.id, s.job_id, s.version FROM stage_runs s
                    JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE'
                   WHERE s.status = 'READY' AND s.not_before <= now() ORDER BY s.not_before LIMIT 10 FOR NO KEY UPDATE OF s SKIP LOCKED$q$;
  sweep text := $q$SELECT tenant_id, id, stage_run_id, version, lease_epoch FROM attempts
                     WHERE status IN ('STARTING', 'RUNNING') AND lease_expires_at < now() ORDER BY lease_expires_at LIMIT 100 FOR NO KEY UPDATE SKIP LOCKED$q$;
  relay text := $q$SELECT seq, event_id FROM outbox WHERE published_at IS NULL ORDER BY seq LIMIT 100 FOR UPDATE SKIP LOCKED$q$;
BEGIN
  PERFORM dbtest.expect_eq('the claim query runs as the system role and finds the READY stage runs of both tenants (no tenant setting)',
    dbtest.run_as(claim, 'factory_system'), 'rows=2');
  PERFORM dbtest.expect_eq('the sweep query runs as the system role and finds the expired leases of both tenants',
    dbtest.run_as(sweep, 'factory_system'), 'rows=2');
  PERFORM dbtest.expect_eq('the relay query runs as the system role and finds the unpublished events of both tenants',
    dbtest.run_as(relay, 'factory_system'), 'rows=2');
  PERFORM dbtest.expect_eq('a tenant setting changes nothing for the system role: it was never scoped by it',
    dbtest.run_as(claim, 'factory_system', NULL, NULL, false, dbtest.u(1)::text), 'rows=2');
  PERFORM dbtest.expect_eq('the relay marks events of every tenant as published, touching its two bookkeeping columns',
    dbtest.run_as('UPDATE outbox SET published_at = now(), publish_attempts = publish_attempts + 1', 'factory_system'), 'rows=2');
  PERFORM dbtest.expect_eq('and the application role, as tenant 1, can run the same bookkeeping update on its own events only',
    dbtest.run_as('UPDATE outbox SET published_at = now(), publish_attempts = publish_attempts + 1', 'factory_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the system role can read the migration version table for its start-up check',
    left(dbtest.run_as('SELECT max(version) FROM __diesel_schema_migrations', 'factory_system'), 6), 'rows=1');
END
$$;

-- What it cannot do. Every attempt is made with the system role and no tenant setting.
DO $$
DECLARE
  t text;
  denied text := '';
  got text;
  stmt text;
BEGIN
  -- Every tenant-owned table other than the four it uses cannot even be read.
  FOR t IN SELECT x FROM dbtest.tenant_tables() AS x WHERE x <> ALL (ARRAY['stage_runs', 'jobs', 'attempts', 'outbox']) LOOP
    got := dbtest.run_as(format('SELECT 1 FROM %I', t), 'factory_system');
    IF got NOT LIKE 'ERR:42501:permission denied%' THEN denied := denied || format('%s: %s; ', t, got); END IF;
  END LOOP;
  PERFORM dbtest.expect_eq('the system role cannot read the ledger, the audit log, tokens, approvals, requests or any other table it has no use for', denied, '');
  PERFORM dbtest.expect_true('it cannot read the tenants table either',
    dbtest.run_as('SELECT 1 FROM tenants', 'factory_system') LIKE 'ERR:42501:permission denied%');

  -- On the tables it uses: no whole-row read, no write of any kind.
  denied := '';
  FOREACH stmt IN ARRAY ARRAY[
    'SELECT * FROM stage_runs', 'SELECT * FROM jobs', 'SELECT * FROM attempts',
    'SELECT lease_owner FROM attempts', 'SELECT stage_contract_sha256 FROM stage_runs', 'SELECT normalized_request_sha256 FROM jobs',
    'INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number) VALUES (dbtest.u(1), dbtest.u(1999), dbtest.u(1101), ''INTAKE'', 9)',
    'DELETE FROM stage_runs', 'DELETE FROM jobs', 'DELETE FROM attempts', 'DELETE FROM outbox', 'TRUNCATE stage_runs', 'TRUNCATE outbox',
    'UPDATE stage_runs SET status = ''RUNNING'', lease_epoch = lease_epoch + 1, version = version + 1',
    'UPDATE stage_runs SET version = version + 1', 'UPDATE jobs SET status = ''ACTIVE''',
    'UPDATE attempts SET status = ''LEASE_LOST'', ended_at = now(), version = version + 1',
    'UPDATE outbox SET payload = ''{}''', 'UPDATE outbox SET event_type = ''job.failed''',
    'INSERT INTO outbox (tenant_id, event_id, event_type, job_id, aggregate_type, aggregate_id, aggregate_version, transition_id, correlation_id, occurred_at, producer, payload) VALUES (dbtest.u(1), dbtest.u(1998), ''job.admitted'', dbtest.u(1101), ''job'', dbtest.u(1101), 2, ''J01'', dbtest.u(1), now(), ''x'', ''{}'')'
  ] LOOP
    got := dbtest.run_as(stmt, 'factory_system');
    IF got NOT LIKE 'ERR:%' THEN denied := denied || format('%s -> %s; ', left(stmt, 60), got); END IF;
  END LOOP;
  PERFORM dbtest.expect_eq('the system role is refused a whole-row read of stage runs, jobs and attempts, and every write to them and to the outbox payload', denied, '');

  -- The lock is not a write. With the triggers off, the policy itself refuses the new row.
  PERFORM dbtest.expect_true('the system role can take the lock but a row it updated would be refused by the policy (WITH CHECK false)',
    dbtest.run_as('UPDATE stage_runs SET updated_at = now()', 'factory_system', NULL, NULL, true) LIKE 'ERR:42501:new row violates row-level security policy%');
  PERFORM dbtest.expect_true('and with the triggers on the same update fails too, in the version trigger',
    dbtest.run_as('UPDATE stage_runs SET updated_at = now()', 'factory_system') LIKE 'ERR:23514:%');
  PERFORM dbtest.expect_eq('the stage run table is unchanged by all of that',
    (SELECT count(*) FROM stage_runs WHERE status = 'RUNNING'), 2::bigint);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 5. The two lookups for work that happens before a tenant is known (ADR 0012, section 4).
--
-- Authenticating an API token and binding a webhook to a repository cannot name a tenant: finding it is
-- their job. Two SECURITY DEFINER functions do it, instead of a policy that admits every row of
-- api_tokens and repositories. They return identifiers only, and nothing at all, with no reason, for every
-- kind of miss. They belong to factory_lookup, which has a read-only policy on the columns they use and
-- nothing else; they pin their search path and qualify every name; PUBLIC cannot run them; only
-- factory_resolver can.
--
--   resolve_token(token_hash bytea, audience text)                          -> (tenant_id, principal_id)
--   resolve_installation(github_installation_id bigint, github_repository_id bigint) -> (tenant_id, repository_id)
--
-- The installation lookup takes the repository id as well as the installation id: one installation covers
-- many repositories, so the installation alone does not name one repository. The pair does, because a
-- GitHub repository can belong to one tenant only (repositories.github_repository_id is unique).

-- The catalog facts.
DO $$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT * FROM (VALUES ('resolve_token', 'bytea, text', 'TABLE(tenant_id uuid, principal_id uuid)'),
                                 ('resolve_installation', 'bigint, bigint', 'TABLE(tenant_id uuid, repository_id uuid)')) AS v(name, args, result)
  LOOP
    PERFORM dbtest.expect_eq(f.name || ' is SECURITY DEFINER, STABLE, owned by factory_lookup, with the search path pinned to pg_catalog and pg_temp',
      (SELECT p.prosecdef::text || ' ' || p.provolatile::text || ' ' || p.proowner::regrole::text || ' ' || coalesce(array_to_string(p.proconfig, ','), 'NO CONFIG')
         FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname = f.name),
      'true s factory_lookup search_path=pg_catalog, pg_temp');
    PERFORM dbtest.expect_eq(f.name || ' returns identifiers only: ' || f.result,
      (SELECT pg_get_function_result(p.oid) FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname = f.name), f.result);
    PERFORM dbtest.expect_eq(f.name || ' can be run by factory_resolver and by its owner, and by nobody else (PUBLIC has no EXECUTE)',
      (SELECT string_agg(CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END, ',' ORDER BY a.grantee)
         FROM pg_proc p, aclexplode(p.proacl) a WHERE p.pronamespace = 'public'::regnamespace AND p.proname = f.name AND a.privilege_type = 'EXECUTE'),
      (SELECT string_agg(r, ',' ORDER BY r::regrole::oid) FROM unnest(ARRAY['factory_lookup', 'factory_resolver']) r));
  END LOOP;
END
$$;

-- No other function in the product schema runs with its owner's rights, and every function pins its path
-- (a trigger function runs as the caller, but a caller can put a temporary table or function first).
DO $$
BEGIN
  PERFORM dbtest.expect_eq('the only SECURITY DEFINER functions in the product schema are the two lookups',
    (SELECT string_agg(proname, ',' ORDER BY proname) FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND prosecdef), 'resolve_installation,resolve_token');
  PERFORM dbtest.expect_eq('every function in the product schema pins its search path',
    (SELECT coalesce(string_agg(proname, ',' ORDER BY proname), '') FROM pg_proc
      WHERE pronamespace = 'public'::regnamespace AND NOT EXISTS (SELECT 1 FROM unnest(coalesce(proconfig, '{}')) c WHERE c LIKE 'search_path=%')), '');
  PERFORM dbtest.expect_eq('every view in the product schema runs with the caller''s rights (security_invoker), so a policy applies through it',
    (SELECT coalesce(string_agg(relname, ',' ORDER BY relname), '') FROM pg_class
      WHERE relnamespace = 'public'::regnamespace AND relkind = 'v' AND NOT coalesce(reloptions, '{}') @> ARRAY['security_invoker=true']), '');
END
$$;

-- The behaviour. Tokens: tenant 1 and 2 each have an active one (the fixture). The others are made here.
DO $$
DECLARE
  t1_hash bytea := sha256(convert_to('token-1', 'UTF8'));
  ok_row text := dbtest.u(1) || ' ' || dbtest.u(1002);
BEGIN
  INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, created_at, expires_at, revoked_at) VALUES
    (dbtest.u(1), dbtest.u(1971), dbtest.u(1002), sha256(convert_to('expired', 'UTF8')), 'factory-api', now() - interval '2 days', now() - interval '1 day', NULL),
    (dbtest.u(1), dbtest.u(1972), dbtest.u(1002), sha256(convert_to('revoked', 'UTF8')), 'factory-api', now() - interval '1 hour', now() + interval '1 day', now() - interval '1 minute'),
    (dbtest.u(2), dbtest.u(2971), dbtest.u(2003), sha256(convert_to('service-token', 'UTF8')), 'factory-cli', now() - interval '1 hour', now() + interval '1 day', NULL);
  INSERT INTO principals (tenant_id, id, kind, github_user_id, login, disabled_at)
    VALUES (dbtest.u(1), dbtest.u(1010), 'human', 7010, 'former-colleague', now());
  INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, expires_at)
    VALUES (dbtest.u(1), dbtest.u(1973), dbtest.u(1010), sha256(convert_to('disabled-owner', 'UTF8')), 'factory-api', now() + interval '1 day');

  PERFORM dbtest.expect_eq('resolve_token returns the tenant and the principal for a valid token and audience, to the lookup login with no tenant setting',
    dbtest.run_as(format($q$SELECT 1 FROM resolve_token(%L, 'factory-api') WHERE tenant_id = %L AND principal_id = %L$q$, t1_hash, dbtest.u(1), dbtest.u(1002)), 'factory_resolver'), 'rows=1');
  PERFORM dbtest.expect_eq('it returns tenant 2 for the token of tenant 2, whatever tenant the session is set to (the lookup is not scoped by the setting)',
    dbtest.run_as(format($q$SELECT 1 FROM resolve_token(%L, 'factory-api') WHERE tenant_id = %L$q$, sha256(convert_to('token-2', 'UTF8')), dbtest.u(2)), 'factory_resolver', 1), 'rows=1');
  PERFORM dbtest.expect_eq('a service principal''s token resolves with the principal id of the service',
    dbtest.run_as(format($q$SELECT 1 FROM resolve_token(%L, 'factory-cli') WHERE principal_id = %L$q$, sha256(convert_to('service-token', 'UTF8')), dbtest.u(2003)), 'factory_resolver'), 'rows=1');

  -- Every miss is zero rows and no error.
  PERFORM dbtest.expect_eq('miss: a hash that was never stored', dbtest.run_as(format($q$SELECT * FROM resolve_token(%L, 'factory-api')$q$, sha256(convert_to('never stored', 'UTF8'))), 'factory_resolver'), 'rows=0');
  PERFORM dbtest.expect_eq('miss: the right token presented to another audience', dbtest.run_as(format($q$SELECT * FROM resolve_token(%L, 'factory-cli')$q$, t1_hash), 'factory_resolver'), 'rows=0');
  PERFORM dbtest.expect_eq('miss: an expired token', dbtest.run_as(format($q$SELECT * FROM resolve_token(%L, 'factory-api')$q$, sha256(convert_to('expired', 'UTF8'))), 'factory_resolver'), 'rows=0');
  PERFORM dbtest.expect_eq('miss: a revoked token', dbtest.run_as(format($q$SELECT * FROM resolve_token(%L, 'factory-api')$q$, sha256(convert_to('revoked', 'UTF8'))), 'factory_resolver'), 'rows=0');
  PERFORM dbtest.expect_eq('miss: a token whose owner is disabled', dbtest.run_as(format($q$SELECT * FROM resolve_token(%L, 'factory-api')$q$, sha256(convert_to('disabled-owner', 'UTF8'))), 'factory_resolver'), 'rows=0');
  PERFORM dbtest.expect_eq('miss: a token of a disabled tenant',
    dbtest.run_as(format($q$SELECT * FROM resolve_token(%L, 'factory-api')$q$, sha256(convert_to('token-2', 'UTF8'))), 'factory_resolver', NULL, 'UPDATE tenants SET disabled_at = now() WHERE id = ' || quote_literal(dbtest.u(2))), 'rows=0');
  PERFORM dbtest.expect_eq('miss: a NULL hash and a NULL audience', dbtest.run_as($q$SELECT * FROM resolve_token(NULL, NULL)$q$, 'factory_resolver'), 'rows=0');
  PERFORM dbtest.expect_eq('miss: a hash of the wrong length', dbtest.run_as($q$SELECT * FROM resolve_token('\x00'::bytea, 'factory-api')$q$, 'factory_resolver'), 'rows=0');

  -- Installation and repository.
  PERFORM dbtest.expect_eq('resolve_installation returns the tenant and the repository for a registered pair',
    dbtest.run_as(format($q$SELECT 1 FROM resolve_installation(9001, 8001) WHERE tenant_id = %L AND repository_id = %L$q$, dbtest.u(1), dbtest.u(1001)), 'factory_resolver'), 'rows=1');
  PERFORM dbtest.expect_eq('it returns tenant 2 for the pair of tenant 2',
    dbtest.run_as(format($q$SELECT 1 FROM resolve_installation(9002, 8002) WHERE tenant_id = %L AND repository_id = %L$q$, dbtest.u(2), dbtest.u(2001)), 'factory_resolver', 1), 'rows=1');
  PERFORM dbtest.expect_eq('miss: an installation that is not registered', dbtest.run_as('SELECT * FROM resolve_installation(1, 8001)', 'factory_resolver'), 'rows=0');
  PERFORM dbtest.expect_eq('miss: a repository that is not registered', dbtest.run_as('SELECT * FROM resolve_installation(9001, 1)', 'factory_resolver'), 'rows=0');
  PERFORM dbtest.expect_eq('miss: the installation of tenant 1 with the repository of tenant 2 (the pair must belong together)',
    dbtest.run_as('SELECT * FROM resolve_installation(9001, 8002)', 'factory_resolver'), 'rows=0');
  PERFORM dbtest.expect_eq('miss: a disabled repository',
    dbtest.run_as('SELECT * FROM resolve_installation(9001, 8001)', 'factory_resolver', NULL, 'UPDATE repositories SET enabled = false, version = version + 1 WHERE github_repository_id = 8001'), 'rows=0');
  PERFORM dbtest.expect_eq('miss: a repository of a disabled tenant',
    dbtest.run_as('SELECT * FROM resolve_installation(9002, 8002)', 'factory_resolver', NULL, 'UPDATE tenants SET disabled_at = now() WHERE id = ' || quote_literal(dbtest.u(2))), 'rows=0');
  PERFORM dbtest.expect_eq('miss: NULL arguments', dbtest.run_as('SELECT * FROM resolve_installation(NULL, NULL)', 'factory_resolver'), 'rows=0');
END
$$;

-- Who can run them.
DO $$
DECLARE
  call_token text := $q$SELECT * FROM resolve_token(sha256(convert_to('token-1', 'UTF8')), 'factory-api')$q$;
  call_install text := 'SELECT * FROM resolve_installation(9001, 8001)';
BEGIN
  PERFORM dbtest.expect_true('the tenant role (factory_app) cannot run resolve_token: a compromised worker cannot test token hashes',
    dbtest.run_as(call_token, 'factory_app', 1) LIKE 'ERR:42501:permission denied for function resolve_token%');
  PERFORM dbtest.expect_true('the tenant role cannot run resolve_installation: it cannot learn which tenant holds an installation',
    dbtest.run_as(call_install, 'factory_app', 1) LIKE 'ERR:42501:permission denied for function resolve_installation%');
  PERFORM dbtest.expect_true('the system role cannot run resolve_token', dbtest.run_as(call_token, 'factory_system') LIKE 'ERR:42501:permission denied for function%');
  PERFORM dbtest.expect_true('the system role cannot run resolve_installation', dbtest.run_as(call_install, 'factory_system') LIKE 'ERR:42501:permission denied for function%');
  PERFORM dbtest.expect_true('a role that is a member of nothing (so PUBLIC alone) cannot run them either',
    dbtest.run_as(call_token, 'dbtest_nobody', NULL, 'CREATE ROLE dbtest_nobody NOLOGIN') LIKE 'ERR:42501:permission denied for function resolve_token%'
    AND dbtest.run_as(call_install, 'dbtest_nobody', NULL, 'CREATE ROLE dbtest_nobody NOLOGIN') LIKE 'ERR:42501:permission denied for function resolve_installation%');
  -- The resolver role gets the lookups and no table.
  PERFORM dbtest.expect_true('factory_resolver cannot read api_tokens directly', dbtest.run_as('SELECT 1 FROM api_tokens', 'factory_resolver') LIKE 'ERR:42501:permission denied%');
  PERFORM dbtest.expect_true('factory_resolver cannot read repositories directly', dbtest.run_as('SELECT 1 FROM repositories', 'factory_resolver') LIKE 'ERR:42501:permission denied%');
  PERFORM dbtest.expect_true('factory_resolver cannot read the active token view directly', dbtest.run_as('SELECT 1 FROM active_api_tokens', 'factory_resolver') LIKE 'ERR:42501:permission denied%');
END
$$;

-- An attacker who can create a temporary table and set the search path cannot redirect the lookup to a
-- table of their own. The function qualifies every name and pins its path.
DO $$
DECLARE
  fake_token text := $q$CREATE TEMP TABLE api_tokens (tenant_id uuid, id uuid, principal_id uuid, token_hash bytea, audience text, expires_at timestamptz, revoked_at timestamptz);
                        INSERT INTO api_tokens VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), '\xdeadbeef', 'factory-api', now() + interval '1 day', NULL);
                        CREATE TEMP TABLE active_api_tokens AS SELECT tenant_id, id, principal_id, token_hash, audience, expires_at FROM api_tokens;
                        SET search_path = pg_temp, public;
                        SELECT * FROM public.resolve_token('\xdeadbeef'::bytea, 'factory-api')$q$;
  fake_repo text := $q$CREATE TEMP TABLE repositories (tenant_id uuid, id uuid, github_installation_id bigint, github_repository_id bigint, enabled boolean);
                       INSERT INTO repositories VALUES (gen_random_uuid(), gen_random_uuid(), 5, 6, true);
                       SET search_path = pg_temp, public;
                       SELECT * FROM public.resolve_installation(5, 6)$q$;
BEGIN
  PERFORM dbtest.expect_eq('a temporary table named active_api_tokens, with the search path put first, does not redirect resolve_token', dbtest.run_as(fake_token, 'factory_resolver'), 'rows=0');
  PERFORM dbtest.expect_eq('a temporary table named repositories does not redirect resolve_installation', dbtest.run_as(fake_repo, 'factory_resolver'), 'rows=0');
END
$$;

-- Control: the same attack does redirect a lookup that names its tables without a schema and does not pin
-- its path, so the two checks above can fail. The unsafe function lives in the test schema and is rolled back.
DO $$
DECLARE
  unsafe_setup text := $q$
    GRANT USAGE ON SCHEMA dbtest TO factory_lookup, factory_resolver;
    CREATE FUNCTION dbtest.unsafe_resolve_token(p_token_hash bytea, p_audience text) RETURNS TABLE (tenant_id uuid, principal_id uuid)
      LANGUAGE sql STABLE SECURITY DEFINER AS $f$ SELECT t.tenant_id, t.principal_id FROM active_api_tokens t WHERE t.token_hash = p_token_hash AND t.audience = p_audience $f$;
    ALTER FUNCTION dbtest.unsafe_resolve_token(bytea, text) OWNER TO factory_lookup;
    GRANT EXECUTE ON FUNCTION dbtest.unsafe_resolve_token(bytea, text) TO factory_resolver$q$;
  attack text := $q$CREATE TEMP TABLE active_api_tokens (tenant_id uuid, id uuid, principal_id uuid, token_hash bytea, audience text, expires_at timestamptz);
                    GRANT SELECT ON active_api_tokens TO PUBLIC;
                    INSERT INTO active_api_tokens VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), '\xdeadbeef', 'factory-api', now() + interval '1 day');
                    SET search_path = pg_temp, public;
                    SELECT * FROM dbtest.unsafe_resolve_token('\xdeadbeef'::bytea, 'factory-api')$q$;
BEGIN
  PERFORM dbtest.expect_eq('control: the same attack redirects a lookup that names its tables without a schema and does not pin its path',
    dbtest.run_as(attack, 'factory_resolver', NULL, unsafe_setup), 'rows=1');
END
$$;

-- The lookup role itself: read-only, on the columns the functions use, and only its own policies.
DO $$
BEGIN
  PERFORM dbtest.expect_eq('factory_lookup can read the columns the lookups use, on tenants, principals, api_tokens and repositories, and nothing else',
    (SELECT string_agg(DISTINCT c.relname, ',' ORDER BY c.relname) FROM pg_attribute att JOIN pg_class c ON c.oid = att.attrelid AND c.relnamespace = 'public'::regnamespace, aclexplode(att.attacl) a
      WHERE a.grantee = 'factory_lookup'::regrole AND a.privilege_type = 'SELECT')
    || '|' || (SELECT coalesce(string_agg(DISTINCT c.relname, ',' ORDER BY c.relname), '') FROM pg_class c, aclexplode(c.relacl) a WHERE c.relnamespace = 'public'::regnamespace AND a.grantee = 'factory_lookup'::regrole),
    'api_tokens,principals,repositories,tenants|active_api_tokens');
  PERFORM dbtest.expect_eq('factory_lookup holds no privilege other than SELECT, on any table, view or column',
    (SELECT coalesce(string_agg(DISTINCT a.privilege_type, ','), '') FROM pg_class c, aclexplode(c.relacl) a WHERE c.relnamespace = 'public'::regnamespace AND a.grantee = 'factory_lookup'::regrole AND a.privilege_type <> 'SELECT')
    || (SELECT coalesce(string_agg(DISTINCT a.privilege_type, ','), '') FROM pg_attribute att JOIN pg_class c ON c.oid = att.attrelid AND c.relnamespace = 'public'::regnamespace, aclexplode(att.attacl) a WHERE a.grantee = 'factory_lookup'::regrole AND a.privilege_type <> 'SELECT'), '');
  PERFORM dbtest.expect_true('factory_lookup cannot read the secrets-adjacent columns the lookups do not need (principals.login, repositories.full_name)',
    dbtest.run_as('SELECT login FROM principals', 'factory_lookup') LIKE 'ERR:42501:%' AND dbtest.run_as('SELECT full_name FROM repositories', 'factory_lookup') LIKE 'ERR:42501:%');
  PERFORM dbtest.expect_true('factory_lookup cannot write anything',
    dbtest.run_as('UPDATE api_tokens SET revoked_at = now()', 'factory_lookup') LIKE 'ERR:42501:%'
    AND dbtest.run_as('DELETE FROM api_tokens', 'factory_lookup') LIKE 'ERR:42501:%'
    AND dbtest.run_as('UPDATE tenants SET disabled_at = now()', 'factory_lookup') LIKE 'ERR:42501:%');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 6. The whole set of policies, written out. A policy that is not on this list fails the suite, and so does a
-- missing one: the list is the review surface of the design.

CREATE TEMP TABLE expected_policies (tbl text, policy text, cmd text, role text);
INSERT INTO expected_policies
SELECT t, 'tenant_isolation', '*', 'factory_app' FROM dbtest.tenant_tables() AS t;
INSERT INTO expected_policies VALUES
  ('tenants', 'tenant_self', 'r', 'factory_app'),
  ('tenants', 'lookup_read', 'r', 'factory_lookup'),
  ('principals', 'lookup_read', 'r', 'factory_lookup'),
  ('api_tokens', 'lookup_read', 'r', 'factory_lookup'),
  ('repositories', 'lookup_read', 'r', 'factory_lookup'),
  ('stage_runs', 'system_find', 'r', 'factory_system'),
  ('stage_runs', 'system_lock', 'w', 'factory_system'),
  ('jobs', 'system_find', 'r', 'factory_system'),
  ('attempts', 'system_find', 'r', 'factory_system'),
  ('attempts', 'system_lock', 'w', 'factory_system'),
  ('outbox', 'system_find', 'r', 'factory_system'),
  ('outbox', 'system_relay', 'w', 'factory_system');

CREATE FUNCTION dbtest.policy_set() RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(c.relname || '.' || p.polname || ' ' || p.polcmd::text || ' ' ||
                             CASE WHEN p.polpermissive THEN '' ELSE 'RESTRICTIVE ' END ||
                             (SELECT string_agg(CASE WHEN r = 0 THEN 'PUBLIC' ELSE r::regrole::text END, '+' ORDER BY r) FROM unnest(p.polroles) r), E'\n' ORDER BY c.relname, p.polname), '')
    FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid WHERE c.relnamespace = 'public'::regnamespace
$$;

DO $$
BEGIN
  PERFORM dbtest.expect_eq('the policies in the database are exactly the policies on the list: no extra, none missing, none for PUBLIC, none restrictive',
    dbtest.policy_set(),
    (SELECT string_agg(tbl || '.' || policy || ' ' || cmd || ' ' || role, E'\n' ORDER BY tbl, policy) FROM expected_policies));
  PERFORM dbtest.expect_eq('row-level security is enabled on exactly the 17 tenant-owned tables and tenants, and forced on the 17',
    (SELECT string_agg(relname || CASE WHEN relforcerowsecurity THEN '+force' ELSE '' END, ',' ORDER BY relname) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relrowsecurity),
    (SELECT string_agg(n, ',' ORDER BY sort_key) FROM (SELECT t || '+force' AS n, t AS sort_key FROM dbtest.tenant_tables() t UNION ALL SELECT 'tenants', 'tenants') x));
  PERFORM dbtest.expect_eq('the reference tables carry no policy and no row-level security, and the application role can only read them',
    (SELECT string_agg(relname, ',' ORDER BY relname) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' AND NOT relrowsecurity), '__diesel_schema_migrations,state_machine_edges,state_machine_states,state_machine_transitions');
END
$$;
