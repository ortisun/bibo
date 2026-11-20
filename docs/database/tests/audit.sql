-- Suite: audit
-- Proves NT-AUD-01 (the application role can only INSERT and SELECT on the audit event table),
-- NT-AUD-04 (server-assigned time and sequence), the required fields (actor, policy hash, correlation
-- id), the per-tenant hash chain, and that tampering is found. Concurrent writers and the external
-- (Python) check of the chain are run by scripts/db-test.sh after this file.

DO $$
BEGIN
  PERFORM dbtest.mk_tenant(1);
  PERFORM dbtest.mk_tenant(2);
  PERFORM dbtest.mk_job(1, 1);
  PERFORM dbtest.mk_stage_run(1, 1, 1);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 1. Privileges. The grants are read from the catalog, then each forbidden statement is tried.

DO $$
DECLARE
  priv text;
BEGIN
  FOREACH priv IN ARRAY ARRAY['INSERT', 'SELECT'] LOOP
    PERFORM dbtest.expect_true(format('factory_app holds %s on audit_events', priv), has_table_privilege('factory_app', 'audit_events', priv));
  END LOOP;
  FOREACH priv IN ARRAY ARRAY['UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'] LOOP
    PERFORM dbtest.expect_true(format('factory_app does not hold %s on audit_events', priv), NOT has_table_privilege('factory_app', 'audit_events', priv));
  END LOOP;
  PERFORM dbtest.expect_true('factory_app holds no column-level UPDATE on audit_events either', NOT has_any_column_privilege('factory_app', 'audit_events', 'UPDATE'));
  PERFORM dbtest.expect_true('factory_app owns neither the audit table nor anything else',
    NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.relowner = 'factory_app'::regrole));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. The application role appends events; the database assigns the chain fields (NT-AUD-04).

DO $$
BEGIN
  PERFORM dbtest.exec('SELECT dbtest.audit(1, 1)', 'factory_app');
  PERFORM dbtest.exec('SELECT dbtest.audit(1, 2, ''authorization.decision'')', 'factory_app');
  PERFORM dbtest.expect_eq('the application role appended two audit events', (SELECT count(*) FROM audit_events WHERE tenant_id = dbtest.u(1)), 2::bigint);
  PERFORM dbtest.expect_eq('sequence numbers were assigned 1 and 2',
    (SELECT array_agg(sequence ORDER BY sequence) FROM audit_events WHERE tenant_id = dbtest.u(1)), ARRAY[1, 2]::bigint[]);
  PERFORM dbtest.expect_true('event 1 has no predecessor and event 2 links to the hash of event 1',
    (SELECT a.prev_hash IS NULL AND b.prev_hash = a.hash AND b.prev_sequence = 1
       FROM audit_events a, audit_events b WHERE a.tenant_id = dbtest.u(1) AND b.tenant_id = dbtest.u(1) AND a.sequence = 1 AND b.sequence = 2));
END
$$;

-- A client that supplies its own timestamp, sequence, chain links and hash is overwritten.
DO $$
DECLARE
  rec audit_events%ROWTYPE;
BEGIN
  PERFORM dbtest.exec(format($q$INSERT INTO audit_events (tenant_id, sequence, event_id, actor_type, actor_id, action, subject, decision, reason,
        policy_hash, correlation_id, created_at, prev_sequence, prev_hash, canonical_json, hash)
      VALUES (%L, 999, %L, 'human', 'user-1', 'approval.granted', 'job', 'allow', 'The approver was on the allowlist.', %L, %L,
        '2001-01-01T00:00:00Z', 998, %L, '{"forged":true}', %L)$q$,
      dbtest.u(1), dbtest.u(30), dbtest.sha('policy'), dbtest.u(1500), dbtest.sha('forged prev'), dbtest.sha('forged hash')), 'factory_app');
  SELECT * INTO rec FROM audit_events WHERE event_id = dbtest.u(30);
  PERFORM dbtest.expect_eq('NT-AUD-04: a client-supplied sequence is ignored (the next number is used)', rec.sequence, 3::bigint);
  PERFORM dbtest.expect_true('NT-AUD-04: a client-supplied created_at is ignored (the database clock is used)', rec.created_at > now() - interval '1 minute');
  PERFORM dbtest.expect_true('NT-AUD-04: client-supplied chain links and hash are ignored',
    rec.prev_hash = (SELECT hash FROM audit_events WHERE tenant_id = dbtest.u(1) AND sequence = 2) AND rec.prev_sequence = 2
    AND rec.hash <> dbtest.sha('forged hash') AND rec.canonical_json <> '{"forged":true}');
  PERFORM dbtest.expect_true('NT-AUD-04: created_at never goes backwards along the chain',
    (SELECT bool_and(created_at >= lag_at) FROM (SELECT created_at, lag(created_at) OVER (ORDER BY sequence) AS lag_at FROM audit_events WHERE tenant_id = dbtest.u(1)) x WHERE lag_at IS NOT NULL));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. UPDATE, DELETE, TRUNCATE and DROP fail for the application role (NT-AUD-01), and the owner is
-- stopped by the trigger. The row count never changes.

DO $$
DECLARE
  before bigint := (SELECT count(*) FROM audit_events);
BEGIN
  PERFORM dbtest.expect_error('NT-AUD-01: UPDATE on audit_events is denied for the application role',
    'UPDATE audit_events SET reason = ''edited''', '42501', 'factory_app', NULL, 'permission denied for table audit_events');
  PERFORM dbtest.expect_error('NT-AUD-01: DELETE on audit_events is denied for the application role',
    'DELETE FROM audit_events', '42501', 'factory_app', NULL, 'permission denied for table audit_events');
  PERFORM dbtest.expect_error('NT-AUD-01: TRUNCATE on audit_events is denied for the application role',
    'TRUNCATE audit_events', '42501', 'factory_app', NULL, 'permission denied for table audit_events');
  PERFORM dbtest.expect_error('NT-AUD-01: DROP TABLE audit_events is denied for the application role',
    'DROP TABLE audit_events', '42501', 'factory_app', NULL, 'must be owner of table audit_events');
  PERFORM dbtest.expect_error('NT-AUD-01: ALTER TABLE audit_events is denied for the application role',
    'ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_change', '42501', 'factory_app', NULL, 'must be owner of table audit_events');
  PERFORM dbtest.expect_error('NT-AUD-01: CREATE TRIGGER on audit_events is denied for the application role',
    'CREATE TRIGGER x BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION audit_events_assign()', '42501', 'factory_app');
  PERFORM dbtest.expect_error('the application role cannot create objects in the public schema',
    'CREATE TABLE public.evil (x int)', '42501', 'factory_app', NULL, 'permission denied for schema public');
  PERFORM dbtest.expect_error('owner: UPDATE on audit_events is stopped by the append-only trigger',
    'UPDATE audit_events SET reason = ''edited''', '42501', NULL, NULL, 'audit_events is append-only: UPDATE%');
  PERFORM dbtest.expect_error('owner: DELETE on audit_events is stopped by the append-only trigger',
    'DELETE FROM audit_events', '42501', NULL, NULL, 'audit_events is append-only: DELETE%');
  PERFORM dbtest.expect_error('owner: TRUNCATE on audit_events is stopped by the append-only trigger',
    'TRUNCATE audit_events', '42501', NULL, NULL, 'audit_events is append-only: TRUNCATE%');
  PERFORM dbtest.expect_eq('the audit table still holds the same rows after all those attempts', (SELECT count(*) FROM audit_events), before);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. Required fields: actor, policy hash, correlation id (and the rest) cannot be missing or malformed.

DO $$
DECLARE
  base text := $q$INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, correlation_id)
                  VALUES (%L, %L, %L, %L, %L, 'subject', %L, 'A reason.', %L, %L)$q$;
  t uuid := dbtest.u(1);
  ph text := dbtest.sha('policy');
BEGIN
  PERFORM dbtest.exec(format(base, t, dbtest.u(40), 'service', 'engine', 'gate.result', 'record', ph, dbtest.u(1500)), 'factory_app');
  PERFORM dbtest.expect_eq('a complete event is accepted', (SELECT count(*) FROM audit_events WHERE event_id = dbtest.u(40)), 1::bigint);
  PERFORM dbtest.expect_error('an event with no actor id is rejected', format(base, t, dbtest.u(41), 'service', NULL, 'gate.result', 'record', ph, dbtest.u(1500)), '23502', 'factory_app');
  PERFORM dbtest.expect_error('an event with an empty actor id is rejected', format(base, t, dbtest.u(41), 'service', '', 'gate.result', 'record', ph, dbtest.u(1500)), '23514', 'factory_app');
  PERFORM dbtest.expect_error('an event with no policy hash is rejected', format(base, t, dbtest.u(41), 'service', 'engine', 'gate.result', 'record', NULL, dbtest.u(1500)), '23502', 'factory_app');
  PERFORM dbtest.expect_error('an event with a malformed policy hash is rejected', format(base, t, dbtest.u(41), 'service', 'engine', 'gate.result', 'record', 'abc', dbtest.u(1500)), '23514', 'factory_app', 'audit_events_policy_hash_check');
  PERFORM dbtest.expect_error('an event with no correlation id is rejected', format(base, t, dbtest.u(41), 'service', 'engine', 'gate.result', 'record', ph, NULL), '23502', 'factory_app');
  PERFORM dbtest.expect_error('an event with an unknown actor type is rejected', format(base, t, dbtest.u(41), 'robot', 'engine', 'gate.result', 'record', ph, dbtest.u(1500)), '23514', 'factory_app', 'audit_events_actor_type_check');
  PERFORM dbtest.expect_error('an event with an unknown decision is rejected', format(base, t, dbtest.u(41), 'service', 'engine', 'gate.result', 'maybe', ph, dbtest.u(1500)), '23514', 'factory_app', 'audit_events_decision_check');
  PERFORM dbtest.expect_error('an event with a malformed action is rejected', format(base, t, dbtest.u(41), 'service', 'engine', 'Gate Result', 'record', ph, dbtest.u(1500)), '23514', 'factory_app', 'audit_events_action_check');
  PERFORM dbtest.expect_error('the same event id twice in one tenant is rejected', format(base, t, dbtest.u(40), 'service', 'engine', 'gate.result', 'record', ph, dbtest.u(1500)), '23505', 'factory_app');
  PERFORM dbtest.expect_error('an event for a tenant that does not exist is rejected', format(base, dbtest.u(77), dbtest.u(42), 'service', 'engine', 'gate.result', 'record', ph, dbtest.u(1500)), '23503', 'factory_app', NULL, NULL, 77);
  PERFORM dbtest.expect_error('a stage run without a job is rejected',
    format($q$INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, correlation_id, stage_run_id)
              VALUES (%L, %L, 'service', 'engine', 'gate.result', 's', 'record', 'r', %L, %L, %L)$q$, t, dbtest.u(43), ph, dbtest.u(1500), dbtest.u(1201)),
    '23514', 'factory_app', 'audit_events_stage_run_needs_job');
  PERFORM dbtest.expect_ok('an event that names a job and its stage run is accepted',
    format($q$INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, correlation_id, job_id, stage_run_id)
              VALUES (%L, %L, 'service', 'engine', 'gate.result', 's', 'record', 'r', %L, %L, %L, %L)$q$, t, dbtest.u(44), ph, dbtest.u(1500), dbtest.u(1101), dbtest.u(1201)), 'factory_app');
END
$$;

-- Events that belong to no tenant go to the platform tenant, which has its own chain.
DO $$
BEGIN
  PERFORM dbtest.exec(format($q$INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, correlation_id)
        VALUES ('00000000-0000-0000-0000-000000000001', %L, 'anonymous', 'unknown', 'webhook.rejected', 'delivery', 'deny', 'The signature did not verify.', %L, %L)$q$,
        dbtest.u(50), dbtest.sha('policy'), dbtest.u(1501)), 'factory_app', -1);   -- a session for the platform tenant (Store::begin with its id)
  PERFORM dbtest.expect_eq('an event with no tenant is recorded under the platform tenant, starting its own chain at 1',
    (SELECT sequence FROM audit_events WHERE tenant_id = '00000000-0000-0000-0000-000000000001'), 1::bigint);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 5. The chain is sound, and tampering is found. Tenant 2 gets six events for the tamper cases.

DO $$
DECLARE
  i int;
  t uuid := dbtest.u(2);
  off text := 'SET LOCAL session_replication_role = replica; ';
  probe text := format($q$DO $d$ BEGIN RAISE EXCEPTION 'verify=%%', public.audit_verify_chain(%L); END $d$ $q$, dbtest.u(2));
BEGIN
  FOR i IN 1..6 LOOP
    PERFORM dbtest.exec(format('SELECT dbtest.audit(2, %s)', i), 'factory_app', 2);
  END LOOP;
  PERFORM dbtest.expect_true('an intact chain verifies: audit_verify_chain returns NULL (tenant 2, six events)', public.audit_verify_chain(t) IS NULL);
  PERFORM dbtest.expect_true('an intact chain verifies (tenant 1)', public.audit_verify_chain(dbtest.u(1)) IS NULL);

  PERFORM dbtest.expect_error('editing a column of an event is found at that event (sequence 3)',
    off || format('UPDATE audit_events SET reason = ''edited'' WHERE tenant_id = %L AND sequence = 3; ', t) || probe, 'P0001', NULL, NULL, 'verify=3');
  PERFORM dbtest.expect_error('editing the stored text of an event is found at that event (sequence 2)',
    off || format('UPDATE audit_events SET canonical_json = replace(canonical_json, ''allow'', ''deny'') WHERE tenant_id = %L AND sequence = 2; ', t) || probe, 'P0001', NULL, NULL, 'verify=2');
  PERFORM dbtest.expect_error('replacing a hash is found at that event (sequence 4)',
    off || format('UPDATE audit_events SET hash = %L WHERE tenant_id = %L AND sequence = 4; ', dbtest.sha('x'), t) || probe, 'P0001', NULL, NULL, 'verify=4');
  PERFORM dbtest.expect_error('deleting a middle event is found at the event after the gap (sequence 4)',
    off || format('DELETE FROM audit_events WHERE tenant_id = %L AND sequence = 3; ', t) || probe, 'P0001', NULL, NULL, 'verify=4');
  PERFORM dbtest.expect_error('reordering two events is found at the first one that moved (sequence 3)',
    off || format($q$UPDATE audit_events SET sequence = 100 WHERE tenant_id = %L AND sequence = 3;
                     UPDATE audit_events SET sequence = 3 WHERE tenant_id = %L AND sequence = 4;
                     UPDATE audit_events SET sequence = 4 WHERE tenant_id = %L AND sequence = 100; $q$, t, t, t) || probe, 'P0001', NULL, NULL, 'verify=3');
  PERFORM dbtest.expect_error('rewriting the identity of an event is found at that event (sequence 3)',
    off || format($q$UPDATE audit_events SET event_id = %L WHERE tenant_id = %L AND sequence = 3; $q$, dbtest.u(666), t) || probe, 'P0001', NULL, NULL, 'verify=3');
  -- Known limit, stated as a test so it cannot be forgotten: deleting from the end leaves a sound
  -- prefix. Only the external anchor (the head hash stored outside this database) can see it.
  PERFORM dbtest.expect_error('KNOWN LIMIT: deleting the tail is NOT found by the verifier (the external anchor must catch it)',
    off || format($q$DELETE FROM audit_events WHERE tenant_id = %L AND sequence = 6; $q$, t) || probe, 'P0001', NULL, NULL, 'verify=<NULL>%');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 9. Events with no job, and the platform tenant (ADR 0014, decision 2): Store::record_audit with no job, and
-- Store::record_platform_audit, which writes under the platform tenant. The recipes are in store_model.sql, section 8.

DO $$
DECLARE
  platform uuid := '00000000-0000-0000-0000-000000000001';
  ins text := $q$INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, correlation_id)
                  VALUES (%L, %L, %L, %L, 'webhook.rejected', 'delivery:x', 'deny', 'The signature did not verify.', %L, %L) ON CONFLICT (tenant_id, event_id) DO NOTHING RETURNING sequence$q$;
BEGIN
  PERFORM dbtest.exec(format(ins, dbtest.u(1), dbtest.u(9901), 'anonymous', 'webhook', dbtest.sha('policy'), dbtest.u(9801)), 'factory_app');
  PERFORM dbtest.expect_eq('an event with no job is stored for a tenant, as an anonymous actor', (SELECT actor_type || ':' || (job_id IS NULL)::text FROM audit_events WHERE event_id = dbtest.u(9901)), 'anonymous:true');
  PERFORM dbtest.expect_eq('a replay of the same event id takes no row and no sequence number',
    dbtest.run_as(format(ins, dbtest.u(1), dbtest.u(9901), 'anonymous', 'webhook', dbtest.sha('policy'), dbtest.u(9801)), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.exec(format(ins, platform, dbtest.u(9902), 'anonymous', 'webhook', dbtest.sha('policy'), dbtest.u(9802)), 'factory_app', -1);
  PERFORM dbtest.exec(format(ins, platform, dbtest.u(9903), 'anonymous', 'webhook', dbtest.sha('policy'), dbtest.u(9803)), 'factory_app', -1);
  PERFORM dbtest.expect_eq('two platform events follow each other in the platform tenant''s own chain, and the chain verifies',
    ((SELECT sequence FROM audit_events WHERE event_id = dbtest.u(9903)) - (SELECT sequence FROM audit_events WHERE event_id = dbtest.u(9902)))::text || ' ' || coalesce(audit_verify_chain(platform)::text, 'ok'), '1 ok');
  PERFORM dbtest.expect_eq('a tenant 1 session sees none of the platform events', dbtest.run_as(format('SELECT 1 FROM audit_events WHERE tenant_id = %L', platform), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_error('a tenant 1 session cannot write an event for the platform tenant (the policy)',
    format(ins, platform, dbtest.u(9904), 'anonymous', 'webhook', dbtest.sha('policy'), dbtest.u(9804)), '42501', 'factory_app', NULL, NULL, 1);
END
$$;
