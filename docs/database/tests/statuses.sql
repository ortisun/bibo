-- Suite: statuses
-- Proves (1) every status column rejects an unknown value, (2) the allowed values, the terminal flags,
-- the legal moves and the event names equal docs/architecture/state-machine.json, and (3) the
-- transition trigger accepts exactly the moves in that file and rejects every other pair.
-- The expected values come from the JSON through docs/database/tools/state_machine_sql.py.

-- ---------------------------------------------------------------------------------------------
-- 1. Reference tables equal the JSON.

DO $$
DECLARE
  n bigint;
BEGIN
  SELECT count(*) INTO n FROM (
    (SELECT machine, status, is_initial, is_terminal FROM state_machine_states EXCEPT SELECT * FROM dbtest.expected_states)
    UNION ALL
    (SELECT * FROM dbtest.expected_states EXCEPT SELECT machine, status, is_initial, is_terminal FROM state_machine_states)) d;
  PERFORM dbtest.expect_eq('state_machine_states equals state-machine.json (states, initial and terminal flags)', n, 0::bigint);

  SELECT count(*) INTO n FROM (
    (SELECT machine, transition_id, event, to_status, emits FROM state_machine_transitions EXCEPT SELECT * FROM dbtest.expected_transitions)
    UNION ALL
    (SELECT * FROM dbtest.expected_transitions EXCEPT SELECT machine, transition_id, event, to_status, emits FROM state_machine_transitions)) d;
  PERFORM dbtest.expect_eq('state_machine_transitions equals state-machine.json (ids, events, targets, emitted event names)', n, 0::bigint);

  SELECT count(*) INTO n FROM (
    (SELECT machine, from_status, transition_id FROM state_machine_edges EXCEPT SELECT * FROM dbtest.expected_edges)
    UNION ALL
    (SELECT * FROM dbtest.expected_edges EXCEPT SELECT machine, from_status, transition_id FROM state_machine_edges)) d;
  PERFORM dbtest.expect_eq('state_machine_edges equals state-machine.json (every from state of every transition)', n, 0::bigint);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. Every status column carries a CHECK whose list equals the JSON.

-- The quoted words inside a constraint definition, as a sorted array.
CREATE FUNCTION dbtest.literals(p_table text, p_constraint text) RETURNS text[] LANGUAGE sql AS $$
  SELECT coalesce(array_agg(DISTINCT m[1] ORDER BY m[1]), '{}')
    FROM pg_constraint c, regexp_matches(pg_get_constraintdef(c.oid), '''([A-Za-z_0-9]+)''', 'g') AS m
   WHERE c.conrelid = ('public.' || p_table)::regclass AND c.conname = p_constraint
$$;

CREATE FUNCTION dbtest.machine_states(p_machine text, p_terminal_only boolean DEFAULT false) RETURNS text[] LANGUAGE sql AS $$
  SELECT coalesce(array_agg(status ORDER BY status), '{}') FROM dbtest.expected_states
   WHERE machine = p_machine AND (NOT p_terminal_only OR is_terminal)
$$;

DO $$
DECLARE
  r record;
  status_columns int;
BEGIN
  -- Discover the status columns from the catalog, so a new one cannot be forgotten.
  SELECT count(*) INTO status_columns
    FROM information_schema.columns
   WHERE table_schema = 'public' AND column_name = 'status'
     AND table_name NOT LIKE 'state_machine%' AND table_name <> '__diesel_schema_migrations';
  PERFORM dbtest.expect_eq('there are exactly four status columns, one per state machine', status_columns, 4);

  FOR r IN SELECT * FROM (VALUES
    ('jobs', 'job', 'jobs_terminal_check'),
    ('stage_runs', 'stage_run', 'stage_runs_terminal_check'),
    ('attempts', 'attempt', 'attempts_terminal_check'),
    ('task_nodes', 'task_node', 'task_nodes_terminal_check')) AS v(tbl, machine, terminal_check)
  LOOP
    PERFORM dbtest.expect_eq(r.tbl || '.status CHECK lists exactly the ' || r.machine || ' states of state-machine.json',
      dbtest.literals(r.tbl, r.tbl || '_status_check'), dbtest.machine_states(r.machine));
    PERFORM dbtest.expect_eq(r.tbl || ' terminal CHECK lists exactly the terminal ' || r.machine || ' states of state-machine.json',
      dbtest.literals(r.tbl, r.terminal_check), dbtest.machine_states(r.machine, true));
  END LOOP;

  PERFORM dbtest.expect_eq('stage_runs.stage_kind CHECK lists exactly the pipeline stage kinds of state-machine.json',
    dbtest.literals('stage_runs', 'stage_runs_stage_kind_check'),
    (SELECT array_agg(stage_kind ORDER BY stage_kind) FROM dbtest.expected_stage_kinds));
  PERFORM dbtest.expect_eq('jobs.pipeline_scope CHECK lists exactly the pipeline stage kinds of state-machine.json',
    dbtest.literals('jobs', 'jobs_pipeline_scope_check'),
    (SELECT array_agg(stage_kind ORDER BY stage_kind) FROM dbtest.expected_stage_kinds));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. An unknown status is rejected on every status column. The CHECK is exercised on its own by
-- switching the triggers and foreign keys off for the statement (a superuser setting that only
-- reaches the subtransaction), and the same insert is tried with everything on.

DO $$
DECLARE
  t uuid := dbtest.u(1);
  j uuid := dbtest.u(101);
  sr uuid := dbtest.u(201);
  off text := 'SET LOCAL session_replication_role = replica; ';
BEGIN
  PERFORM dbtest.expect_error('jobs: an unknown status is rejected by the CHECK constraint',
    off || format($q$INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, status, execution_mode, autonomy_level,
                       pipeline_scope, correlation_id)
                     VALUES (%L, %L, %L, %L, 'BOGUS', 'production', 'L1', ARRAY['INTAKE'], %L)$q$, t, j, dbtest.u(1001), dbtest.u(1002), dbtest.u(501)),
    '23514', NULL, 'jobs_status_check');
  PERFORM dbtest.expect_error('stage_runs: an unknown status is rejected by the CHECK constraint',
    off || format($q$INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number, status)
                     VALUES (%L, %L, %L, 'INTAKE', 1, 'BOGUS')$q$, t, sr, j),
    '23514', NULL, 'stage_runs_status_check');
  PERFORM dbtest.expect_error('attempts: an unknown status is rejected by the CHECK constraint',
    off || format($q$INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, status, lease_epoch, deadline_at)
                     VALUES (%L, %L, %L, %L, 1, 'BOGUS', 1, now() + interval '1 hour')$q$, t, dbtest.u(301), j, sr),
    '23514', NULL, 'attempts_status_check');
  PERFORM dbtest.expect_error('task_nodes: an unknown status is rejected by the CHECK constraint',
    off || format($q$INSERT INTO task_nodes (tenant_id, id, job_id, stage_run_id, task_key, plan_sha256, status)
                     VALUES (%L, %L, %L, %L, 'task-one', %L, 'BOGUS')$q$, t, dbtest.u(401), j, sr, dbtest.sha('plan')),
    '23514', NULL, 'task_nodes_status_check');

  PERFORM dbtest.expect_error('jobs: a pipeline scope longer than the 14 stage kinds is rejected',
    off || format($q$INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level,
                       pipeline_scope, correlation_id)
                     VALUES (%L, %L, %L, %L, 'production', 'L1', array_fill('INTAKE'::text, ARRAY[15]), %L)$q$, t, j, dbtest.u(1001), dbtest.u(1002), dbtest.u(501)),
    '23514', NULL, 'jobs_pipeline_scope_check');
  PERFORM dbtest.expect_error('jobs: an empty pipeline scope is rejected',
    off || format($q$INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level,
                       pipeline_scope, correlation_id)
                     VALUES (%L, %L, %L, %L, 'production', 'L1', '{}', %L)$q$, t, j, dbtest.u(1001), dbtest.u(1002), dbtest.u(501)),
    '23514', NULL, 'jobs_pipeline_scope_check');

  -- Lower case or a typo is also unknown.
  PERFORM dbtest.expect_error('stage_runs: a lower-case status is rejected',
    off || format($q$INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number, status)
                     VALUES (%L, %L, %L, 'INTAKE', 1, 'pending')$q$, t, sr, j),
    '23514', NULL, 'stage_runs_status_check');
  PERFORM dbtest.expect_error('stage_runs: an unknown stage kind is rejected',
    off || format($q$INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number)
                     VALUES (%L, %L, %L, 'DEPLOY', 1)$q$, t, sr, j),
    '23514', NULL, 'stage_runs_stage_kind_check');
END
$$;

-- With the triggers on, an unknown status never gets in either (the initial-state trigger answers first).
DO $$
BEGIN
  PERFORM dbtest.mk_tenant(1);
  PERFORM dbtest.expect_error('jobs: with triggers on, an unknown status on INSERT is rejected',
    format($q$INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, status, execution_mode, autonomy_level,
                       pipeline_scope, correlation_id)
              VALUES (%L, %L, %L, %L, 'BOGUS', 'production', 'L1', ARRAY['INTAKE'], %L)$q$,
           dbtest.u(1), dbtest.u(101), dbtest.u(1001), dbtest.u(1002), dbtest.u(501)),
    '23514');
  PERFORM dbtest.mk_job(1, 1);
  PERFORM dbtest.expect_error('jobs: with triggers on, an unknown status on UPDATE is rejected',
    format($q$UPDATE jobs SET status = 'BOGUS', version = version + 1 WHERE id = %L$q$, dbtest.u(1101)), '23514');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. The transition trigger equals the JSON, for every ordered pair of states of every machine.
-- Each machine gets a scratch table that has only a status column and the real trigger function, so
-- no other rule can hide a wrong answer.

DO $$
DECLARE
  m text;
  a text;
  b text;
  expected_legal boolean;
  got_legal boolean;
  pairs int := 0;
  mismatches text := '';
BEGIN
  FOR m IN SELECT DISTINCT machine FROM dbtest.expected_states ORDER BY 1 LOOP
    EXECUTE format('CREATE TABLE dbtest.scratch_%s (id int PRIMARY KEY, status text)', m);
    EXECUTE format('CREATE TRIGGER machine BEFORE INSERT OR UPDATE ON dbtest.scratch_%s FOR EACH ROW EXECUTE FUNCTION public.enforce_status_transition(%L)', m, m);

    FOR a IN SELECT status FROM dbtest.expected_states WHERE machine = m LOOP
      -- Insert: only the initial state is allowed.
      BEGIN
        EXECUTE format('INSERT INTO dbtest.scratch_%s VALUES (1, %L)', m, a);
        got_legal := true;
        EXECUTE format('DELETE FROM dbtest.scratch_%s', m);
      EXCEPTION WHEN check_violation THEN
        got_legal := false;
      END;
      SELECT is_initial INTO expected_legal FROM dbtest.expected_states WHERE machine = m AND status = a;
      IF got_legal <> expected_legal THEN
        mismatches := mismatches || format(' insert(%s,%s) expected %s got %s;', m, a, expected_legal, got_legal);
      END IF;

      FOR b IN SELECT status FROM dbtest.expected_states WHERE machine = m AND status <> a LOOP
        -- Place a row in state a without the trigger, then try a to b with it.
        EXECUTE format('ALTER TABLE dbtest.scratch_%s DISABLE TRIGGER machine', m);
        EXECUTE format('INSERT INTO dbtest.scratch_%s VALUES (1, %L)', m, a);
        EXECUTE format('ALTER TABLE dbtest.scratch_%s ENABLE TRIGGER machine', m);
        BEGIN
          EXECUTE format('UPDATE dbtest.scratch_%s SET status = %L', m, b);
          got_legal := true;
        EXCEPTION WHEN check_violation THEN
          got_legal := false;
        END;
        EXECUTE format('DELETE FROM dbtest.scratch_%s', m);
        SELECT EXISTS (
          SELECT 1 FROM dbtest.expected_edges e JOIN dbtest.expected_transitions t USING (machine, transition_id)
           WHERE e.machine = m AND e.from_status = a AND t.to_status = b) INTO expected_legal;
        pairs := pairs + 1;
        IF got_legal <> expected_legal THEN
          mismatches := mismatches || format(' %s %s->%s expected %s got %s;', m, a, b, expected_legal, got_legal);
        END IF;
      END LOOP;
    END LOOP;
  END LOOP;
  PERFORM dbtest.expect_eq(format('the transition trigger gives the answer of state-machine.json for all %s ordered pairs of states and every insert', pairs), mismatches, '');
END
$$;

-- The trigger is attached, with the right machine, to each real table.
DO $$
DECLARE
  r record;
  n int;
BEGIN
  FOR r IN SELECT * FROM (VALUES ('jobs', 'job'), ('stage_runs', 'stage_run'), ('attempts', 'attempt'), ('task_nodes', 'task_node')) AS v(tbl, machine) LOOP
    SELECT count(*) INTO n FROM pg_trigger t
     WHERE t.tgrelid = ('public.' || r.tbl)::regclass AND NOT t.tgisinternal
       AND pg_get_triggerdef(t.oid) LIKE '%BEFORE INSERT OR UPDATE ON%'
       AND pg_get_triggerdef(t.oid) LIKE format('%%enforce_status_transition(''%s'')', r.machine);
    PERFORM dbtest.expect_eq(r.tbl || ' has the BEFORE INSERT OR UPDATE transition trigger for the ' || r.machine || ' machine', n, 1);
  END LOOP;
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 5. Behaviour on the real tables, through the application role.

DO $$
BEGIN
  PERFORM dbtest.mk_stage_run(1, 1, 1);
  PERFORM dbtest.expect_error('stage_runs: PENDING to PASSED is not a legal move',
    format($q$UPDATE stage_runs SET status = 'PASSED', gate_outcome = 'PASSED', finished_at = now(), version = version + 1 WHERE id = %L$q$, dbtest.u(1201)),
    '23514', 'factory_app', 'stage_runs_legal_transition');
  PERFORM dbtest.expect_ok('stage_runs: PENDING to READY is legal',
    format($q$UPDATE stage_runs SET status = 'READY', version = version + 1 WHERE id = %L$q$, dbtest.u(1201)), 'factory_app');
  PERFORM dbtest.expect_error('stage_runs: a new run cannot be inserted already RUNNING',
    format($q$INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number, status)
              VALUES (%L, %L, %L, 'SPECIFICATION', 1, 'RUNNING')$q$, dbtest.u(1), dbtest.u(1299), dbtest.u(1101)),
    '23514', 'factory_app', 'stage_runs_initial_state');
END
$$;
