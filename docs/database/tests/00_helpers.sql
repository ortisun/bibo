-- Test helpers. Loaded before every suite into a clone of the migrated template database.
-- Nothing here is part of the product schema: it lives in the dbtest schema of a throwaway clone.
--
-- Style: a check that holds prints "ok - <label>" as a NOTICE. A check that fails raises an
-- exception, psql stops (ON_ERROR_STOP), and the suite exits non-zero.

CREATE SCHEMA dbtest;

-- A deterministic UUID for readable fixtures: u(1) is 00000000-0000-7000-8000-000000000001.
CREATE FUNCTION dbtest.u(n bigint) RETURNS uuid LANGUAGE sql IMMUTABLE AS $$
  SELECT ('00000000-0000-7000-8000-' || lpad(to_hex(n), 12, '0'))::uuid
$$;

CREATE FUNCTION dbtest.sha(seed text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT 'sha256:' || encode(sha256(convert_to(seed, 'UTF8')), 'hex')
$$;

CREATE FUNCTION dbtest.pass(label text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  RAISE NOTICE 'ok - %', label;
END
$$;

CREATE FUNCTION dbtest.fail(label text, detail text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'NOT OK - %: %', label, detail USING ERRCODE = 'P0001';
END
$$;

-- Which tenant a statement run as the application role is made for. Since ADR 0012 the application role
-- sees only the rows of the tenant named by the transaction-local setting factory.tenant_id, which is what
-- Store::begin sets. dbtest.tenant is the default for the whole test run (tenant 1, set at the end of this
-- file as a database setting). A call can name another tenant with as_tenant, pass 0 for a transaction that
-- made no setting (the setting then reads as an empty string, as it does on a reused connection), or pass -1
-- for the platform tenant that owns the audit events of requests no tenant could be found for.
CREATE FUNCTION dbtest.use_tenant(t int) RETURNS void LANGUAGE sql AS $$
  SELECT set_config('dbtest.tenant', t::text, false) IS NOT NULL
$$;

-- SET LOCAL ROLE for the rest of the transaction (or subtransaction). For the application role it also
-- makes the tenant setting. Any other role gets an empty setting, so a test of the system scope or a
-- lookup function cannot lean on a tenant left over from an earlier call.
CREATE FUNCTION dbtest.become(p_role text, p_tenant int DEFAULT NULL) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  t int := coalesce(p_tenant, nullif(current_setting('dbtest.tenant', true), '')::int, 0);
  tenant_text text := CASE WHEN p_role <> 'factory_app' THEN ''
                           WHEN t = -1 THEN '00000000-0000-0000-0000-000000000001'   -- the platform tenant
                           WHEN t > 0 THEN dbtest.u(t)::text
                           ELSE '' END;
BEGIN
  EXECUTE format('SET LOCAL ROLE %I', p_role);
  PERFORM set_config('factory.tenant_id', tenant_text, true);
END
$$;

-- Run a statement and require it to fail with the given SQLSTATE. The statement runs in a
-- subtransaction that is always rolled back, so a statement that wrongly succeeds leaves nothing
-- behind. as_role switches to that role for the statement only (see dbtest.become for the tenant).
-- constraint_like and msg_like are optional LIKE patterns for the constraint name and the message.
CREATE FUNCTION dbtest.expect_error(
  label text, stmt text, expected_state text,
  as_role text DEFAULT NULL, constraint_like text DEFAULT NULL, msg_like text DEFAULT NULL, as_tenant int DEFAULT NULL
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  got_state text;
  got_msg text;
  got_constraint text;
BEGIN
  BEGIN
    IF as_role IS NOT NULL THEN
      PERFORM dbtest.become(as_role, as_tenant);
    END IF;
    EXECUTE stmt;
    RAISE EXCEPTION 'statement succeeded' USING ERRCODE = 'XX999';
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS got_state = RETURNED_SQLSTATE, got_msg = MESSAGE_TEXT, got_constraint = CONSTRAINT_NAME;
  END;
  IF got_state = 'XX999' THEN
    PERFORM dbtest.fail(label, 'the statement succeeded but had to fail: ' || stmt);
  END IF;
  IF got_state <> expected_state THEN
    PERFORM dbtest.fail(label, format('expected SQLSTATE %s, got %s (%s) for: %s', expected_state, got_state, got_msg, stmt));
  END IF;
  IF constraint_like IS NOT NULL AND coalesce(got_constraint, '') NOT LIKE constraint_like THEN
    PERFORM dbtest.fail(label, format('expected constraint like %s, got %s (%s)', constraint_like, got_constraint, got_msg));
  END IF;
  IF msg_like IS NOT NULL AND got_msg NOT LIKE msg_like THEN
    PERFORM dbtest.fail(label, format('expected message like %s, got: %s', msg_like, got_msg));
  END IF;
  PERFORM dbtest.pass(label);
END
$$;

-- Run a statement that must work, optionally as another role. The effect stays.
CREATE FUNCTION dbtest.exec(stmt text, as_role text DEFAULT NULL, as_tenant int DEFAULT NULL) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF as_role IS NOT NULL THEN
    PERFORM dbtest.become(as_role, as_tenant);
  END IF;
  EXECUTE stmt;
  IF as_role IS NOT NULL THEN
    RESET ROLE;
  END IF;
EXCEPTION WHEN OTHERS THEN
  RESET ROLE;
  RAISE;
END
$$;

-- Run a statement that must work and check it. The effect is rolled back.
CREATE FUNCTION dbtest.expect_ok(label text, stmt text, as_role text DEFAULT NULL, as_tenant int DEFAULT NULL) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  got_state text;
  got_msg text;
BEGIN
  BEGIN
    IF as_role IS NOT NULL THEN
      PERFORM dbtest.become(as_role, as_tenant);
    END IF;
    EXECUTE stmt;
    RAISE EXCEPTION 'rollback marker' USING ERRCODE = 'XX998';
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS got_state = RETURNED_SQLSTATE, got_msg = MESSAGE_TEXT;
  END;
  IF got_state <> 'XX998' THEN
    PERFORM dbtest.fail(label, format('the statement failed with %s (%s): %s', got_state, got_msg, stmt));
  END IF;
  PERFORM dbtest.pass(label);
END
$$;

-- Run one statement as a group role, with the tenant setting Store::begin would make, in a subtransaction
-- that is always rolled back. Reports 'rows=N' (rows returned or changed) or 'ERR:<sqlstate>:<message>'.
--   p_setup         statements run first, as the owner (a temporary GRANT, for instance)
--   p_triggers_off  run with session_replication_role = replica, which switches off user triggers and foreign
--                   keys but NOT policies. Used to reach the policy check without a trigger answering first.
--   p_setting       a raw value for factory.tenant_id instead of a tenant number (for 'not-a-uuid')
CREATE FUNCTION dbtest.run_as(
  p_stmt text, p_role text, p_tenant int DEFAULT NULL, p_setup text DEFAULT NULL,
  p_triggers_off boolean DEFAULT false, p_setting text DEFAULT NULL
) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
  res text;
  st text;
  msg text;
BEGIN
  BEGIN
    IF p_setup IS NOT NULL THEN
      EXECUTE p_setup;
    END IF;
    IF p_triggers_off THEN
      SET LOCAL session_replication_role = replica;
    END IF;
    PERFORM dbtest.become(p_role, p_tenant);
    IF p_setting IS NOT NULL THEN
      PERFORM set_config('factory.tenant_id', p_setting, true);
    END IF;
    EXECUTE p_stmt;
    GET DIAGNOSTICS n = ROW_COUNT;
    res := 'rows=' || n;
    RAISE EXCEPTION 'rollback' USING ERRCODE = 'XX998';
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS st = RETURNED_SQLSTATE, msg = MESSAGE_TEXT;
    IF st <> 'XX998' THEN
      res := 'ERR:' || st || ':' || msg;
    END IF;
  END;
  RETURN res;
END
$$;

-- Try a statement and report what happened, without failing: 'ok' when it ran, otherwise
-- '<SQLSTATE>:<constraint name>'. The statement is always rolled back. For a test that compares many
-- attempts with an expected table and wants one summary line instead of one line per attempt.
CREATE FUNCTION dbtest.try_stmt(stmt text, as_role text DEFAULT NULL, as_tenant int DEFAULT NULL) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  got_state text;
  got_constraint text;
BEGIN
  BEGIN
    IF as_role IS NOT NULL THEN
      PERFORM dbtest.become(as_role, as_tenant);
    END IF;
    EXECUTE stmt;
    RAISE EXCEPTION 'rollback marker' USING ERRCODE = 'XX998';
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS got_state = RETURNED_SQLSTATE, got_constraint = CONSTRAINT_NAME;
  END;
  RETURN CASE WHEN got_state = 'XX998' THEN 'ok' ELSE got_state || ':' || coalesce(got_constraint, '') END;
END
$$;

CREATE FUNCTION dbtest.expect_true(label text, condition boolean, detail text DEFAULT '') RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF condition IS DISTINCT FROM true THEN
    PERFORM dbtest.fail(label, 'condition is ' || coalesce(condition::text, 'NULL') || ' ' || detail);
  END IF;
  PERFORM dbtest.pass(label);
END
$$;

CREATE FUNCTION dbtest.expect_eq(label text, actual anyelement, expected anyelement) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF actual IS DISTINCT FROM expected THEN
    PERFORM dbtest.fail(label, format('expected %s, got %s', expected, actual));
  END IF;
  PERFORM dbtest.pass(label);
END
$$;

-- Count rows with a query string, for before/after checks.
CREATE FUNCTION dbtest.count(query text) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE n bigint;
BEGIN
  EXECUTE 'SELECT count(*) FROM (' || query || ') q' INTO n;
  RETURN n;
END
$$;

-- ---------------------------------------------------------------------------------------------
-- Fixtures. Tenant t owns ids t*1000 + k, so tenant 1 has u(1001) and tenant 2 has u(2001).
--   k=1 repository, k=2 human principal, k=3 service principal, 100+j job j, 200+j+s stage runs ...
-- The builders run as the table owner, so they are not subject to the application role grants.

CREATE FUNCTION dbtest.mk_tenant(t int) RETURNS void LANGUAGE sql AS $$
  INSERT INTO tenants (id, slug, display_name) VALUES (dbtest.u(t), 'tenant-' || t, 'Tenant ' || t);
  INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch)
    VALUES (dbtest.u(t), dbtest.u(t * 1000 + 1), 9000 + t, 8000 + t, 'org' || t || '/repo', 'main');
  INSERT INTO principals (tenant_id, id, kind, github_user_id, login)
    VALUES (dbtest.u(t), dbtest.u(t * 1000 + 2), 'human', 7000 + t, 'person' || t);
  INSERT INTO principals (tenant_id, id, kind)
    VALUES (dbtest.u(t), dbtest.u(t * 1000 + 3), 'service');
$$;

-- Job j of tenant t: id t*1000+100+j.
CREATE FUNCTION dbtest.mk_job(t int, j int, mode text DEFAULT 'production') RETURNS uuid LANGUAGE sql AS $$
  INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level,
                    pipeline_scope, correlation_id)
  VALUES (dbtest.u(t), dbtest.u(t * 1000 + 100 + j), dbtest.u(t * 1000 + 1), dbtest.u(t * 1000 + 2), mode, 'L1',
          ARRAY['INTAKE', 'REPOSITORY_INTELLIGENCE', 'SPECIFICATION'], dbtest.u(t * 1000 + 500 + j))
  RETURNING id
$$;

-- Stage run s (1..99) of job j of tenant t: id t*1000+200+s.
CREATE FUNCTION dbtest.mk_stage_run(t int, j int, s int, kind text DEFAULT 'INTAKE', run_number int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $$
  INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number)
  VALUES (dbtest.u(t), dbtest.u(t * 1000 + 200 + s), dbtest.u(t * 1000 + 100 + j), kind, run_number)
  RETURNING id
$$;

-- Move a row through legal states using the owner. Bumps the version by one per call.
CREATE FUNCTION dbtest.set_status(tbl text, t int, id uuid, new_status text, extra text DEFAULT '') RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
BEGIN
  EXECUTE format('UPDATE %I SET status = %L, version = version + 1 %s WHERE tenant_id = %L AND id = %L',
                 tbl, new_status, extra, dbtest.u(t), id);
  GET DIAGNOSTICS n = ROW_COUNT;  -- EXECUTE does not set FOUND
  IF n <> 1 THEN
    RAISE EXCEPTION 'set_status changed % rows of % for %', n, tbl, id;
  END IF;
END
$$;

-- The ledger entry document, as the application would canonicalize it (key order is not
-- RFC 8785 here: the database hashes the text it is given and does not canonicalize).
CREATE FUNCTION dbtest.ledger_doc(
  p_job uuid, p_stage_run uuid, p_seq bigint, p_prev_hash text, p_entry_id uuid,
  p_kind text DEFAULT 'assumption', p_mode text DEFAULT 'production', p_fidelity text DEFAULT 'real',
  p_assurance text DEFAULT NULL, p_invalidates uuid[] DEFAULT '{}', p_attempt uuid DEFAULT NULL,
  p_recorded_at timestamptz DEFAULT '2026-10-27T12:00:00Z'
) RETURNS text LANGUAGE sql AS $$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'schema_version', 1,
    'metadata', jsonb_build_object(
      'entry_id', p_entry_id, 'job_id', p_job, 'stage_run_id', p_stage_run, 'attempt_id', p_attempt,
      'sequence', p_seq, 'recorded_at', to_char(p_recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
      'execution_mode', p_mode,
      'recorded_by', jsonb_build_object('component', 'workflow.gate-evaluator', 'fidelity', p_fidelity)),
    'claim', jsonb_build_object('statement', 'The build gate passed on the job branch.', 'kind', p_kind,
                                'assurance_level', p_assurance),
    'evidence', '[]'::jsonb,
    'confidence', jsonb_build_object('level', 'high', 'rationale', 'The gate report hash matches the stored report.'),
    'invalidates', to_jsonb(p_invalidates)
  )
  || jsonb_build_object('prev_entry_hash', p_prev_hash))::text
$$;

-- entry_hash = 'sha256:' || hex(sha256(prev_entry_hash text, newline, canonical document text)).
CREATE FUNCTION dbtest.ledger_hash(p_prev_hash text, p_doc text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT 'sha256:' || encode(sha256(convert_to(coalesce(p_prev_hash, '') || E'\n' || p_doc, 'UTF8')), 'hex')
$$;

-- Insert one ledger entry. The previous hash is given, so a test can forge a link; append_entry below
-- looks it up. Overrides let a test break one thing at a time: p_doc replaces the hashed document,
-- p_hash the entry hash, p_col_kind the claim_kind column. Returns the entry hash.
CREATE FUNCTION dbtest.insert_entry(
  t int, p_job uuid, p_stage_run uuid, p_seq bigint, p_prev text,
  p_kind text DEFAULT 'assumption', p_mode text DEFAULT 'production', p_fidelity text DEFAULT 'real',
  p_assurance text DEFAULT NULL, p_invalidates uuid[] DEFAULT '{}', p_attempt uuid DEFAULT NULL,
  p_entry_id uuid DEFAULT NULL, p_doc text DEFAULT NULL, p_hash text DEFAULT NULL, p_col_kind text DEFAULT NULL
) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  doc text;
  h text;
  eid uuid := coalesce(p_entry_id, md5(p_job::text || ':' || p_seq)::uuid);
BEGIN
  doc := coalesce(p_doc, dbtest.ledger_doc(p_job, p_stage_run, p_seq, p_prev, eid, p_kind, p_mode, p_fidelity, p_assurance, p_invalidates, p_attempt));
  h := coalesce(p_hash, dbtest.ledger_hash(p_prev, doc));
  INSERT INTO ledger_entries (tenant_id, job_id, sequence, entry_id, stage_run_id, attempt_id, recorded_at,
                              execution_mode, recorded_component, recorded_fidelity, claim_kind, assurance_level,
                              confidence_level, invalidates, prev_entry_hash, entry_hash, canonical_json)
  VALUES (dbtest.u(t), p_job, p_seq, eid, p_stage_run, p_attempt, '2026-10-27T12:00:00Z',
          p_mode, 'workflow.gate-evaluator', p_fidelity, coalesce(p_col_kind, p_kind), p_assurance,
          'high', p_invalidates, p_prev, h, doc);
  RETURN h;
END
$$;

-- Append entry number p_seq after the entry the table already holds at p_seq - 1.
CREATE FUNCTION dbtest.append_entry(
  t int, p_job uuid, p_stage_run uuid, p_seq bigint,
  p_kind text DEFAULT 'assumption', p_mode text DEFAULT 'production', p_fidelity text DEFAULT 'real',
  p_assurance text DEFAULT NULL, p_invalidates uuid[] DEFAULT '{}', p_attempt uuid DEFAULT NULL
) RETURNS text LANGUAGE sql AS $$
  SELECT dbtest.insert_entry(t, p_job, p_stage_run, p_seq,
    (SELECT entry_hash FROM ledger_entries WHERE tenant_id = dbtest.u(t) AND job_id = p_job AND sequence = p_seq - 1),
    p_kind, p_mode, p_fidelity, p_assurance, p_invalidates, p_attempt)
$$;

-- An audit event with the fields the application supplies. The database assigns the rest.
CREATE FUNCTION dbtest.audit(t int, n int, p_action text DEFAULT 'webhook.received') RETURNS void LANGUAGE sql AS $$
  INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason,
                            policy_hash, correlation_id)
  VALUES (dbtest.u(t), dbtest.u(t * 1000000 + 900000 + n), 'service', 'api.webhook', p_action, 'delivery:' || n,
          'allow', 'The delivery passed signature verification.', dbtest.sha('policy'), dbtest.u(t * 1000 + 500));
$$;

-- The application role runs some statements through these helpers (SET LOCAL ROLE), so it needs to
-- reach them. This grants it nothing on the product schema. Once the row-level security migrations exist
-- the system role runs a few of them too; the roles are cluster wide, so they exist before this file loads.
GRANT USAGE ON SCHEMA dbtest TO factory_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA dbtest TO factory_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA dbtest GRANT EXECUTE ON FUNCTIONS TO factory_app;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'factory_system') THEN
    GRANT USAGE ON SCHEMA dbtest TO factory_system;
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA dbtest TO factory_system;
    ALTER DEFAULT PRIVILEGES IN SCHEMA dbtest GRANT EXECUTE ON FUNCTIONS TO factory_system;
  END IF;
END
$$;

-- The default tenant for statements run as the application role: tenant 1 (see dbtest.become). Stored as a
-- database setting, so every suite session started after this file picks it up. dbtest.use_tenant(n)
-- changes it for one session.
DO $$
BEGIN
  EXECUTE format('ALTER DATABASE %I SET dbtest.tenant = %L', current_database(), '1');
END
$$;
