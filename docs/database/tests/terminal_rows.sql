-- Suite: terminal_rows
-- Proves invariant INV-04: a terminal stage run is never edited, except that a supersedable one
-- (PASSED, or SKIPPED since ADR 0010) can become SUPERSEDED. Which states are supersedable is read from
-- state-machine.json through the edges (the supersede transition S20), not written down here.
-- Also covers the rules that sit next to it: only legal moves, new rows start in the initial state,
-- every update raises the version by exactly one, the lease epoch moves only with a claim, and a
-- finished attempt keeps its result (INV-05).

DO $$
BEGIN
  PERFORM dbtest.mk_tenant(1);
  PERFORM dbtest.mk_job(1, 1);
  -- One run for every terminal state, plus live ones. Ids 1201 to 1209.
  PERFORM dbtest.mk_stage_run(1, 1, 1, 'INTAKE');
  PERFORM dbtest.mk_stage_run(1, 1, 2, 'REPOSITORY_INTELLIGENCE');
  PERFORM dbtest.mk_stage_run(1, 1, 3, 'SPECIFICATION');
  PERFORM dbtest.mk_stage_run(1, 1, 4, 'DOMAIN_DISCOVERY');
  PERFORM dbtest.mk_stage_run(1, 1, 5, 'ARCHITECTURE');
  PERFORM dbtest.mk_stage_run(1, 1, 6, 'TASK_PLANNING');
  PERFORM dbtest.mk_stage_run(1, 1, 7, 'REVIEW');
  PERFORM dbtest.mk_stage_run(1, 1, 8, 'DOCUMENTING');
  PERFORM dbtest.mk_stage_run(1, 1, 9, 'VALIDATION');
  PERFORM dbtest.mk_stage_run(1, 1, 10, 'DELIVERY');
END
$$;

-- Walk the runs into their terminal states through legal moves, as the owner.
DO $$
DECLARE
  claim text := ', lease_epoch = lease_epoch + 1';
  fin text := ', finished_at = now()';
BEGIN
  -- 1201 PASSED: PENDING, READY, RUNNING (claim), GATING, PASSED.
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1201), 'READY');
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1201), 'RUNNING', claim);
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1201), 'GATING');
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1201), 'PASSED', fin || ', gate_outcome = ''PASSED''');
  -- 1207 PASSED too, kept for the supersede cases.
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1207), 'READY');
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1207), 'RUNNING', claim);
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1207), 'GATING');
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1207), 'PASSED', fin || ', gate_outcome = ''PASSED''');
  -- 1202 CANCELLED.
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1202), 'CANCELLED', fin);
  -- 1203 SKIPPED.
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1203), 'SKIPPED', fin || ', gate_outcome = ''NOT_APPLICABLE''');
  -- 1204 FAILED.
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1204), 'READY');
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1204), 'RUNNING', claim);
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1204), 'FAILED', fin);
  -- 1205 REWORK_REQUESTED.
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1205), 'READY');
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1205), 'RUNNING', claim);
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1205), 'GATING');
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1205), 'REWORK_REQUESTED', fin);
  -- 1206 SUPERSEDED straight from PENDING.
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1206), 'SUPERSEDED', fin || ', superseded_at = now()');
  -- 1208 stays PENDING and moves to READY: a live run for the positive controls.
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1208), 'READY');
  -- 1210 SKIPPED too, kept for the supersede cases (1203 is used up by the edit tests).
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1210), 'SKIPPED', fin || ', gate_outcome = ''NOT_APPLICABLE''');
  -- 1209 is a live run in GATING, to test a PASSED move that has no gate outcome.
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1209), 'READY');
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1209), 'RUNNING', claim);
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1209), 'GATING');
  PERFORM dbtest.pass('the owner walked nine runs through legal moves (PASSED x2, CANCELLED, SKIPPED x2, FAILED, REWORK_REQUESTED, SUPERSEDED, READY)');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 1. No edit of a terminal run, whatever the column, for the application role and for the owner.

DO $$
DECLARE
  r record;
  edit text;
BEGIN
  FOR r IN SELECT * FROM (VALUES
    (1201, 'PASSED'), (1202, 'CANCELLED'), (1203, 'SKIPPED'), (1204, 'FAILED'), (1205, 'REWORK_REQUESTED'), (1206, 'SUPERSEDED'))
    AS v(n, state)
  LOOP
    edit := format('UPDATE stage_runs SET max_attempts = 5, version = version + 1 WHERE id = %L', dbtest.u(r.n));
    PERFORM dbtest.expect_error(format('%s run: an UPDATE of a plain column is refused for the application role', r.state),
      edit, '23514', 'factory_app', 'stage_runs_terminal_is_immutable');
    PERFORM dbtest.expect_error(format('%s run: an UPDATE of a plain column is refused for the owner too', r.state),
      edit, '23514', NULL, 'stage_runs_terminal_is_immutable');
    PERFORM dbtest.expect_error(format('%s run: moving it back to READY is refused', r.state),
      format('UPDATE stage_runs SET status = ''READY'', finished_at = NULL, version = version + 1 WHERE id = %L', dbtest.u(r.n)),
      '23514', 'factory_app', 'stage_runs_terminal_is_immutable');
  END LOOP;
  PERFORM dbtest.expect_error('a SUPERSEDED run cannot be superseded again',
    format('UPDATE stage_runs SET superseded_at = now(), version = version + 1 WHERE id = %L', dbtest.u(1206)),
    '23514', 'factory_app', 'stage_runs_terminal_is_immutable');
  PERFORM dbtest.expect_error('a terminal run cannot be deleted by the application role',
    format('DELETE FROM stage_runs WHERE id = %L', dbtest.u(1201)), '42501', 'factory_app');
  PERFORM dbtest.expect_error('an update that changes nothing is refused too (it would still bump the version)',
    format('UPDATE stage_runs SET version = version + 1 WHERE id = %L', dbtest.u(1202)), '23514', 'factory_app', 'stage_runs_terminal_is_immutable');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. The one exception: a supersedable terminal run (PASSED or SKIPPED) becomes SUPERSEDED, with
-- nothing else changed.

DO $$
BEGIN
  PERFORM dbtest.expect_error('PASSED to SUPERSEDED is refused when it also changes another column (max_attempts)',
    format('UPDATE stage_runs SET status = ''SUPERSEDED'', superseded_at = now(), max_attempts = 7, version = version + 1 WHERE id = %L', dbtest.u(1207)),
    '23514', 'factory_app', 'stage_runs_terminal_is_immutable');
  PERFORM dbtest.expect_error('PASSED to SUPERSEDED is refused when it also rewrites the gate outcome',
    format('UPDATE stage_runs SET status = ''SUPERSEDED'', superseded_at = now(), gate_outcome = ''FAILED'', version = version + 1 WHERE id = %L', dbtest.u(1207)),
    '23514', 'factory_app', 'stage_runs_terminal_is_immutable');
  PERFORM dbtest.expect_error('PASSED to SUPERSEDED is refused without superseded_at (the row would be inconsistent)',
    format('UPDATE stage_runs SET status = ''SUPERSEDED'', version = version + 1 WHERE id = %L', dbtest.u(1207)),
    '23514', 'factory_app', 'stage_runs_superseded_check');
  PERFORM dbtest.exec(
    format('UPDATE stage_runs SET status = ''SUPERSEDED'', superseded_at = now(), version = version + 1 WHERE id = %L', dbtest.u(1207)), 'factory_app');
  PERFORM dbtest.expect_eq('PASSED to SUPERSEDED with nothing else changed is accepted for the application role',
    (SELECT status FROM stage_runs WHERE id = dbtest.u(1207)), 'SUPERSEDED');
  PERFORM dbtest.expect_true('the supersede kept the original gate outcome and finish time',
    (SELECT gate_outcome = 'PASSED' AND finished_at IS NOT NULL AND superseded_at IS NOT NULL FROM stage_runs WHERE id = dbtest.u(1207)));
  PERFORM dbtest.expect_error('and the superseded run is then frozen like any other terminal run',
    format('UPDATE stage_runs SET max_attempts = 2, version = version + 1 WHERE id = %L', dbtest.u(1207)),
    '23514', 'factory_app', 'stage_runs_terminal_is_immutable');
  PERFORM dbtest.expect_error('FAILED is terminal and not supersedable: FAILED to SUPERSEDED is refused',
    format('UPDATE stage_runs SET status = ''SUPERSEDED'', superseded_at = now(), version = version + 1 WHERE id = %L', dbtest.u(1204)),
    '23514', 'factory_app', 'stage_runs_terminal_is_immutable');
END
$$;

-- SKIPPED is supersedable too (ADR 0010, decision 2): the skip was decided on recorded inputs, and when an
-- input changes the decision is made again in a new run. The old SKIPPED run must not stay in place, or it
-- would go on satisfying the stages that require it.
DO $$
BEGIN
  PERFORM dbtest.expect_error('SKIPPED to SUPERSEDED is refused when it also changes another column (max_attempts)',
    format('UPDATE stage_runs SET status = ''SUPERSEDED'', superseded_at = now(), max_attempts = 7, version = version + 1 WHERE id = %L', dbtest.u(1210)),
    '23514', 'factory_app', 'stage_runs_terminal_is_immutable');
  PERFORM dbtest.expect_error('SKIPPED to SUPERSEDED is refused when it also rewrites the gate outcome',
    format('UPDATE stage_runs SET status = ''SUPERSEDED'', superseded_at = now(), gate_outcome = ''PASSED'', version = version + 1 WHERE id = %L', dbtest.u(1210)),
    '23514', 'factory_app', 'stage_runs_terminal_is_immutable');
  PERFORM dbtest.expect_error('SKIPPED to SUPERSEDED is refused without superseded_at (the row would be inconsistent)',
    format('UPDATE stage_runs SET status = ''SUPERSEDED'', version = version + 1 WHERE id = %L', dbtest.u(1210)),
    '23514', 'factory_app', 'stage_runs_superseded_check');
  PERFORM dbtest.exec(
    format('UPDATE stage_runs SET status = ''SUPERSEDED'', superseded_at = now(), version = version + 1 WHERE id = %L', dbtest.u(1210)), 'factory_app');
  PERFORM dbtest.expect_eq('SKIPPED to SUPERSEDED with nothing else changed is accepted for the application role',
    (SELECT status FROM stage_runs WHERE id = dbtest.u(1210)), 'SUPERSEDED');
  PERFORM dbtest.expect_true('the supersede of a skipped run kept its NOT_APPLICABLE outcome and finish time',
    (SELECT gate_outcome = 'NOT_APPLICABLE' AND finished_at IS NOT NULL AND superseded_at IS NOT NULL FROM stage_runs WHERE id = dbtest.u(1210)));
  PERFORM dbtest.expect_error('and the superseded skipped run is then frozen like any other terminal run',
    format('UPDATE stage_runs SET max_attempts = 2, version = version + 1 WHERE id = %L', dbtest.u(1210)),
    '23514', 'factory_app', 'stage_runs_terminal_is_immutable');
END
$$;

-- Nothing else leaves a terminal state. For every terminal state and every other status, the move is
-- accepted exactly when state-machine.json has an edge for it, and it is refused with the terminal-row
-- constraint otherwise. The edges come from the JSON through dbtest.expected_edges, so a new supersedable
-- state in the file fails here until a migration follows.
CREATE TEMP TABLE terminal_fixture (status text PRIMARY KEY, run_id uuid);
INSERT INTO terminal_fixture VALUES
  ('PASSED', dbtest.u(1201)), ('CANCELLED', dbtest.u(1202)), ('SKIPPED', dbtest.u(1203)),
  ('FAILED', dbtest.u(1204)), ('REWORK_REQUESTED', dbtest.u(1205)), ('SUPERSEDED', dbtest.u(1206));

DO $$
DECLARE
  f record;
  target record;
  stmt text;
  got text;
  expected_allowed boolean;
  mismatches text := '';
  pairs int := 0;
  allowed_pairs text;
BEGIN
  PERFORM dbtest.expect_eq('the fixture holds one run for every terminal state of the stage run machine',
    (SELECT array_agg(status ORDER BY status) FROM terminal_fixture),
    (SELECT array_agg(status ORDER BY status) FROM dbtest.expected_states WHERE machine = 'stage_run' AND is_terminal));

  FOR f IN SELECT * FROM terminal_fixture ORDER BY status LOOP
    FOR target IN SELECT status FROM dbtest.expected_states WHERE machine = 'stage_run' AND status <> f.status ORDER BY status LOOP
      stmt := format('UPDATE stage_runs SET status = %L, %s version = version + 1 WHERE id = %L',
                     target.status, CASE WHEN target.status = 'SUPERSEDED' THEN 'superseded_at = now(),' ELSE '' END, f.run_id);
      got := dbtest.try_stmt(stmt, 'factory_app');
      SELECT EXISTS (
        SELECT 1 FROM dbtest.expected_edges e JOIN dbtest.expected_transitions t USING (machine, transition_id)
         WHERE e.machine = 'stage_run' AND e.from_status = f.status AND t.to_status = target.status) INTO expected_allowed;
      pairs := pairs + 1;
      IF expected_allowed AND got <> 'ok' THEN
        mismatches := mismatches || format(' %s->%s is in the JSON but was refused (%s);', f.status, target.status, got);
      ELSIF NOT expected_allowed AND got <> '23514:stage_runs_terminal_is_immutable' THEN
        mismatches := mismatches || format(' %s->%s is not in the JSON but gave %s;', f.status, target.status, got);
      END IF;
    END LOOP;
  END LOOP;
  PERFORM dbtest.expect_eq(format('all %s moves out of a terminal state follow state-machine.json: the application role is refused every move the file lacks', pairs), mismatches, '');

  SELECT string_agg(e.from_status || '->' || t.to_status, ', ' ORDER BY e.from_status) INTO allowed_pairs
    FROM dbtest.expected_edges e JOIN dbtest.expected_transitions t USING (machine, transition_id)
    JOIN dbtest.expected_states s ON s.machine = e.machine AND s.status = e.from_status
   WHERE e.machine = 'stage_run' AND s.is_terminal;
  PERFORM dbtest.expect_eq('the only moves out of a terminal state in the file are PASSED and SKIPPED to SUPERSEDED', allowed_pairs, 'PASSED->SUPERSEDED, SKIPPED->SUPERSEDED');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. Live runs stay editable, and the other row rules.

DO $$
BEGIN
  PERFORM dbtest.expect_ok('a READY run can still be edited (the budget can be raised)',
    format('UPDATE stage_runs SET max_attempts = 4, version = version + 1 WHERE id = %L', dbtest.u(1208)), 'factory_app');
  PERFORM dbtest.expect_error('an update that does not raise the version is refused',
    format('UPDATE stage_runs SET max_attempts = 4 WHERE id = %L', dbtest.u(1208)), '23514', 'factory_app', 'stage_runs_version_bump');
  PERFORM dbtest.expect_error('an update that raises the version by two is refused',
    format('UPDATE stage_runs SET max_attempts = 4, version = version + 2 WHERE id = %L', dbtest.u(1208)), '23514', 'factory_app', 'stage_runs_version_bump');
  PERFORM dbtest.expect_error('READY to PASSED is not a legal move',
    format('UPDATE stage_runs SET status = ''PASSED'', gate_outcome = ''PASSED'', finished_at = now(), version = version + 1 WHERE id = %L', dbtest.u(1208)),
    '23514', 'factory_app', 'stage_runs_legal_transition');
  PERFORM dbtest.expect_error('a run cannot be PASSED without a gate outcome',
    format('UPDATE stage_runs SET status = ''PASSED'', finished_at = now(), version = version + 1 WHERE id = %L', dbtest.u(1209)),
    '23514', 'factory_app', 'stage_runs_passed_has_outcome');
  PERFORM dbtest.expect_error('a terminal status needs finished_at (CANCELLED without it is refused)',
    format('UPDATE stage_runs SET status = ''CANCELLED'', version = version + 1 WHERE id = %L', dbtest.u(1208)),
    '23514', 'factory_app', 'stage_runs_terminal_check');
  PERFORM dbtest.expect_error('finished_at on a live run is refused',
    format('UPDATE stage_runs SET finished_at = now(), version = version + 1 WHERE id = %L', dbtest.u(1208)),
    '23514', 'factory_app', 'stage_runs_terminal_check');
  PERFORM dbtest.expect_error('the application role cannot rewrite the job a run belongs to',
    format('UPDATE stage_runs SET job_id = %L, version = version + 1 WHERE id = %L', dbtest.u(1101), dbtest.u(1208)), '42501', 'factory_app');
  PERFORM dbtest.expect_error('the application role cannot change the tenant of a run',
    format('UPDATE stage_runs SET tenant_id = %L, version = version + 1 WHERE id = %L', dbtest.u(2), dbtest.u(1208)), '42501', 'factory_app');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. The lease epoch moves only with a claim (READY to RUNNING), by exactly one.

DO $$
BEGIN
  PERFORM dbtest.expect_error('lease_epoch cannot change without a claim',
    format('UPDATE stage_runs SET lease_epoch = lease_epoch + 1, version = version + 1 WHERE id = %L', dbtest.u(1208)),
    '23514', 'factory_app', 'stage_runs_lease_epoch_moves_with_claim');
  PERFORM dbtest.expect_error('READY to RUNNING without raising the epoch is refused',
    format('UPDATE stage_runs SET status = ''RUNNING'', version = version + 1 WHERE id = %L', dbtest.u(1208)),
    '23514', 'factory_app', 'stage_runs_lease_epoch_moves_with_claim');
  PERFORM dbtest.expect_error('READY to RUNNING raising the epoch by two is refused',
    format('UPDATE stage_runs SET status = ''RUNNING'', lease_epoch = lease_epoch + 2, version = version + 1 WHERE id = %L', dbtest.u(1208)),
    '23514', 'factory_app', 'stage_runs_lease_epoch_moves_with_claim');
  PERFORM dbtest.expect_error('the epoch cannot go down',
    format('UPDATE stage_runs SET status = ''RUNNING'', lease_epoch = lease_epoch - 1, version = version + 1 WHERE id = %L', dbtest.u(1208)),
    '23514', 'factory_app');
  PERFORM dbtest.exec(
    format('UPDATE stage_runs SET status = ''RUNNING'', lease_epoch = lease_epoch + 1, version = version + 1 WHERE id = %L', dbtest.u(1208)), 'factory_app');
  PERFORM dbtest.expect_eq('READY to RUNNING with the epoch raised by one is accepted',
    (SELECT status || ':' || lease_epoch FROM stage_runs WHERE id = dbtest.u(1208)), 'RUNNING:1');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 5. A new row starts in its initial state; other tables of the same family follow the same rules.

DO $$
BEGIN
  PERFORM dbtest.expect_error('a stage run cannot be inserted already PASSED',
    format($q$INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number, status, gate_outcome, finished_at)
              VALUES (%L, %L, %L, 'VALIDATION', 1, 'PASSED', 'PASSED', now())$q$, dbtest.u(1), dbtest.u(1290), dbtest.u(1101)),
    '23514', 'factory_app', 'stage_runs_initial_state');
  PERFORM dbtest.expect_error('a job cannot be inserted already COMPLETED',
    format($q$INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, status, execution_mode, autonomy_level, pipeline_scope, correlation_id, terminal_at)
              VALUES (%L, %L, %L, %L, 'COMPLETED', 'production', 'L1', ARRAY['INTAKE'], %L, now())$q$, dbtest.u(1), dbtest.u(1190), dbtest.u(1001), dbtest.u(1002), dbtest.u(1590)),
    '23514', 'factory_app', 'jobs_initial_state');
  PERFORM dbtest.expect_error('a job needs terminal_at exactly when it is terminal (COMPLETED without it is refused)',
    format($q$UPDATE jobs SET status = 'ACTIVE', version = version + 1 WHERE id = %L$q$, dbtest.u(1101)) || format($q$; UPDATE jobs SET status = 'COMPLETED', version = version + 1 WHERE id = %L$q$, dbtest.u(1101)),
    '23514', 'factory_app', 'jobs_terminal_check');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 6. A finished attempt keeps its result (INV-05). Run 1208 is RUNNING at epoch 1.

DO $$
DECLARE
  a1 uuid := dbtest.u(1301);
BEGIN
  PERFORM dbtest.exec(format($q$INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
        VALUES (%L, %L, %L, %L, 1, 'worker-a', 1, now() + interval '1 minute', now() + interval '1 hour')$q$, dbtest.u(1), a1, dbtest.u(1101), dbtest.u(1208)), 'factory_app');
  PERFORM dbtest.exec(format($q$UPDATE attempts SET status = 'RUNNING', version = version + 1 WHERE id = %L$q$, a1), 'factory_app');
  PERFORM dbtest.exec(format($q$UPDATE attempts SET status = 'LEASE_LOST', ended_at = now(), version = version + 1 WHERE id = %L$q$, a1), 'factory_app');
  PERFORM dbtest.expect_eq('the attempt reached LEASE_LOST through legal moves', (SELECT status FROM attempts WHERE id = a1), 'LEASE_LOST');

  PERFORM dbtest.expect_error('a zombie worker cannot write a result onto its LEASE_LOST attempt',
    format($q$UPDATE attempts SET status = 'SUCCEEDED', version = version + 1 WHERE id = %L$q$, a1), '23514', 'factory_app');
  PERFORM dbtest.expect_error('a zombie worker cannot extend the lease of a finished attempt, even without a status in its WHERE clause',
    format($q$UPDATE attempts SET lease_expires_at = now() + interval '1 hour', last_heartbeat_at = now(), version = version + 1 WHERE id = %L$q$, a1),
    '23514', 'factory_app', 'attempts_terminal_is_immutable');
  PERFORM dbtest.expect_error('a zombie worker cannot attach an output to a finished attempt',
    format($q$UPDATE attempts SET output_sha256 = %L, version = version + 1 WHERE id = %L$q$, dbtest.sha('late output'), a1), '23514', 'factory_app');
  PERFORM dbtest.expect_ok('the sandbox teardown facts can still be recorded on a finished attempt',
    format($q$UPDATE attempts SET sandbox_leaked = true, sandbox_id = 'sbx-1', version = version + 1 WHERE id = %L$q$, a1), 'factory_app');
  PERFORM dbtest.expect_error('the lease epoch of an attempt never changes',
    format($q$UPDATE attempts SET lease_epoch = 2, version = version + 1 WHERE id = %L$q$, a1), '42501', 'factory_app');
  PERFORM dbtest.expect_error('not even the owner can change the lease epoch of an attempt',
    format($q$UPDATE attempts SET lease_epoch = 2, version = version + 1 WHERE id = %L$q$, a1), '23514', NULL, 'attempts_lease_epoch_is_fixed');
  PERFORM dbtest.expect_error('LEASE_LOST cannot go back to RUNNING',
    format($q$UPDATE attempts SET status = 'RUNNING', ended_at = NULL, version = version + 1 WHERE id = %L$q$, a1), '23514', 'factory_app');
END
$$;
