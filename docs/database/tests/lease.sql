-- Suite: lease
-- Proves the lease and claim rules (ADR 0001, 0007 and 0014; invariant INV-05; threat T-25; NT-LSE-01 and
-- NT-LSE-02 at the database level): a claim has one winner, an attempt holds the current epoch, a
-- zombie worker's writes are rejected, a forged renewal changes nothing, a retry back-off is honoured,
-- and lease time is judged by the database clock. The concurrent races run from scripts/db-test.sh
-- after this file.
--
-- The claim protocol of ports v1.1 has two steps with two roles, and this file holds the reference SQL of
-- each, which docs/database/for-the-storage-crate.md quotes:
--   find_claim_candidates    dbtest.find_candidates     system role: READY runs of ACTIVE jobs whose not_before
--                                                       has passed, (not_before, id) order, FOR NO KEY UPDATE
--                                                       SKIP LOCKED. Identifiers only. Writes nothing.
--   start_attempt            dbtest.start_attempt       tenant role: lock the run and share-lock its job, decide
--                                                       (not_found, conflict, job_not_active, backing_off,
--                                                       epoch_exhausted, attempt_limit), then READY -> RUNNING
--                                                       with lease_epoch + 1 and the attempt row, in that order.
--   find_due_attempts        dbtest.find_due_attempts   system role: lease expired (A07), deadline passed (A06),
--                                                       teardown deadline passed (A10).
--   the move of a due one    dbtest.settle_due          tenant role: compare and swap on version and epoch.
-- The claim locks with FOR NO KEY UPDATE, which excludes other claimers but not the writers of ledger,
-- audit and outbox rows that point at the stage run through a foreign key. Here both steps of a claim run in
-- one transaction; in the engine they are two, and the compare and swap and the unique index of one live
-- attempt per stage run decide the winner (the shell races, also through two real logins in the `rls` suite).
-- The lease lives on the attempt: a retry (S05) waits for no lease, because the failed attempt is terminal in
-- the transaction that moves the run back to READY.

DO $$
BEGIN
  PERFORM dbtest.mk_tenant(1);
  PERFORM dbtest.mk_tenant(2);
  PERFORM dbtest.mk_job(1, 1);
  PERFORM dbtest.set_status('jobs', 1, dbtest.u(1101), 'ACTIVE');
END
$$;

-- find_claim_candidates. System role, identifiers only. A candidate is a hint: another worker may find the
-- same one, and start_attempt decides.
CREATE FUNCTION dbtest.find_candidates(p_limit int DEFAULT 10)
RETURNS TABLE (tenant_id uuid, stage_run_id uuid, job_id uuid, version bigint, not_before timestamptz) LANGUAGE plpgsql AS $$
BEGIN
  SET LOCAL ROLE factory_system;
  RETURN QUERY
  SELECT s.tenant_id, s.id, s.job_id, s.version, s.not_before
    FROM stage_runs s
    JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE'
   WHERE s.status = 'READY' AND s.not_before <= now()
   ORDER BY s.not_before, s.id
   LIMIT p_limit
   FOR NO KEY UPDATE OF s SKIP LOCKED;   -- not FOR UPDATE: see the lock mode check in scripts/db-test.sh
  RESET ROLE;
EXCEPTION WHEN OTHERS THEN
  RESET ROLE;
  RAISE;
END
$$;

-- start_attempt, as the tenant role with the setting for the tenant that step 1 found. One call is the
-- statement sequence the storage crate runs in a tenant transaction:
--   1. read the job id of the run (it never changes), then lock in the order job, stage run:
--      SELECT status FROM jobs ... FOR SHARE            a concurrent pause or cancel of the job waits for this
--                                                       decision, or this decision sees the new status; a ledger or
--                                                       outbox insert (KEY SHARE on the job) does not wait;
--      SELECT ... FROM stage_runs ... FOR NO KEY UPDATE the run, with the attempt number and the window.
--      The order job, stage run, attempt, task node is the same everywhere (docs/database/for-the-storage-crate.md),
--      so two transactions cannot wait for each other. A deadlock that happens anyway is SQLSTATE 40P01: retry.
--   2. the decision from what was read, with the names of the port: not_found, conflict (status or version
--      moved, or another worker won), job_not_active, backing_off, epoch_exhausted, attempt_limit;
--   3. UPDATE stage_runs: READY -> RUNNING, lease_epoch + 1, compare and swap on version;
--   4. INSERT the attempt: number previous + 1, the epoch just granted, lease and deadline from the database clock.
-- The outbox event (stage_run.started) and the audit record belong to the same transaction and are not shown.
CREATE FUNCTION dbtest.start_attempt(
  p_tenant uuid, p_stage_run uuid, p_expected bigint, p_worker text,
  p_ttl interval DEFAULT interval '30 seconds', p_timeout interval DEFAULT interval '1 hour'
) RETURNS TABLE (outcome text, attempt_id uuid) LANGUAGE plpgsql AS $$
DECLARE
  r record;
  the_job uuid;
  the_job_status text;
  new_attempt uuid := gen_random_uuid();
  new_epoch bigint;
BEGIN
  SET LOCAL ROLE factory_app;
  PERFORM set_config('factory.tenant_id', p_tenant::text, true);
  SELECT s.job_id INTO the_job FROM stage_runs s WHERE s.tenant_id = p_tenant AND s.id = p_stage_run;
  IF FOUND THEN
    SELECT j.status INTO the_job_status FROM jobs j WHERE j.tenant_id = p_tenant AND j.id = the_job FOR SHARE;
    SELECT s.status AS run_status, s.version AS run_version, s.lease_epoch, s.job_id, s.max_attempts,
           s.attempts_before_last_answer AS window_start, (s.not_before <= now()) AS due,
           (SELECT coalesce(max(a.attempt_number), 0) FROM attempts a WHERE a.tenant_id = s.tenant_id AND a.stage_run_id = s.id) AS last_number
      INTO r
      FROM stage_runs s
     WHERE s.tenant_id = p_tenant AND s.id = p_stage_run
       FOR NO KEY UPDATE;
  END IF;
  IF the_job IS NULL THEN
    outcome := 'not_found';
  ELSIF r.run_status <> 'READY' OR r.run_version <> p_expected THEN
    outcome := 'conflict';
  ELSIF the_job_status <> 'ACTIVE' THEN
    outcome := 'job_not_active';
  ELSIF NOT r.due THEN
    outcome := 'backing_off';
  ELSIF r.lease_epoch = 9223372036854775807 THEN
    outcome := 'epoch_exhausted';
  ELSIF r.last_number + 1 - r.window_start > r.max_attempts THEN
    outcome := 'attempt_limit';
  ELSE
    UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, version = version + 1
     WHERE tenant_id = p_tenant AND id = p_stage_run AND version = p_expected AND status = 'READY'
    RETURNING lease_epoch INTO new_epoch;
    INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
    VALUES (p_tenant, new_attempt, r.job_id, p_stage_run, r.last_number + 1, p_worker, new_epoch, now() + p_ttl, now() + p_timeout);
    outcome := 'started';
    attempt_id := new_attempt;
  END IF;
  RESET ROLE;
  RETURN NEXT;
EXCEPTION WHEN OTHERS THEN
  RESET ROLE;
  RAISE;
END
$$;

-- Claim one READY stage run of an ACTIVE job: find, then start. Returns the new attempt id, or NULL when there
-- is nothing to claim or another claimer got there first.
CREATE FUNCTION dbtest.claim(p_worker text) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE
  c record;
  started record;
BEGIN
  SELECT * INTO c FROM dbtest.find_candidates(1);
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  SELECT * INTO started FROM dbtest.start_attempt(c.tenant_id, c.stage_run_id, c.version, p_worker);
  RETURN started.attempt_id;
END
$$;

-- Renew a lease (AttemptOps::heartbeat). The fence is the WHERE clause: tenant, attempt, owner, epoch, liveness
-- (a CANCELLING attempt is live, and is told to tear down by the status it gets back), and a lease that has not
-- already expired by the database clock.
CREATE FUNCTION dbtest.renew(p_tenant uuid, p_attempt uuid, p_worker text, p_epoch bigint) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
BEGIN
  UPDATE attempts SET lease_expires_at = now() + interval '30 seconds', last_heartbeat_at = now(), version = version + 1
   WHERE tenant_id = p_tenant AND id = p_attempt AND lease_owner = p_worker AND lease_epoch = p_epoch
     AND status IN ('STARTING', 'RUNNING', 'CANCELLING') AND lease_expires_at > now();
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n = 1;
END
$$;

-- find_due_attempts. System role. The three questions of the sweeper, by the database clock, oldest due first,
-- locked FOR NO KEY UPDATE SKIP LOCKED (FOR UPDATE would block a ledger append that points at the attempt).
-- A lease that lapsed is A07, a deadline that passed is A06 (both only while STARTING or RUNNING), and a teardown
-- deadline that passed is A10 (only while CANCELLING).
CREATE FUNCTION dbtest.find_due_attempts(p_reason text, p_limit int DEFAULT 100)
RETURNS TABLE (tenant_id uuid, job_id uuid, stage_run_id uuid, attempt_id uuid, version bigint, lease_epoch bigint) LANGUAGE plpgsql AS $$
BEGIN
  SET LOCAL ROLE factory_system;
  IF p_reason = 'lease_expired' THEN
    RETURN QUERY SELECT a.tenant_id, a.job_id, a.stage_run_id, a.id, a.version, a.lease_epoch
      FROM attempts a WHERE a.status IN ('STARTING', 'RUNNING') AND a.lease_expires_at < now()
      ORDER BY a.lease_expires_at LIMIT p_limit FOR NO KEY UPDATE SKIP LOCKED;
  ELSIF p_reason = 'deadline_passed' THEN
    RETURN QUERY SELECT a.tenant_id, a.job_id, a.stage_run_id, a.id, a.version, a.lease_epoch
      FROM attempts a WHERE a.status IN ('STARTING', 'RUNNING') AND a.deadline_at < now()
      ORDER BY a.deadline_at LIMIT p_limit FOR NO KEY UPDATE SKIP LOCKED;
  ELSIF p_reason = 'teardown_deadline_passed' THEN
    RETURN QUERY SELECT a.tenant_id, a.job_id, a.stage_run_id, a.id, a.version, a.lease_epoch
      FROM attempts a WHERE a.status = 'CANCELLING' AND a.teardown_deadline_at < now()
      ORDER BY a.teardown_deadline_at LIMIT p_limit FOR NO KEY UPDATE SKIP LOCKED;
  ELSE
    RAISE EXCEPTION 'unknown reason %', p_reason;
  END IF;
  RESET ROLE;
EXCEPTION WHEN OTHERS THEN
  RESET ROLE;
  RAISE;
END
$$;

-- The move of one due attempt (transition_attempt for A07, A06 or A10), as the tenant role: compare and swap on
-- version, fenced by the epoch the sweeper just read, and the due condition again by the database clock.
-- True when this call moved it.
CREATE FUNCTION dbtest.settle_due(p_reason text, p_tenant uuid, p_attempt uuid, p_version bigint, p_epoch bigint) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
BEGIN
  SET LOCAL ROLE factory_app;
  PERFORM set_config('factory.tenant_id', p_tenant::text, true);
  IF p_reason = 'lease_expired' THEN
    UPDATE attempts SET status = 'LEASE_LOST', ended_at = now(), version = version + 1
     WHERE tenant_id = p_tenant AND id = p_attempt AND version = p_version AND lease_epoch = p_epoch
       AND status IN ('STARTING', 'RUNNING') AND lease_expires_at < now();
  ELSIF p_reason = 'deadline_passed' THEN
    UPDATE attempts SET status = 'TIMED_OUT', ended_at = now(), version = version + 1
     WHERE tenant_id = p_tenant AND id = p_attempt AND version = p_version AND lease_epoch = p_epoch
       AND status IN ('STARTING', 'RUNNING') AND deadline_at < now();
  ELSE
    -- A10: the force kill. Removal could not be confirmed, so the sandbox is flagged as leaked.
    UPDATE attempts SET status = 'CANCELLED', ended_at = now(), sandbox_leaked = true, version = version + 1
     WHERE tenant_id = p_tenant AND id = p_attempt AND version = p_version AND lease_epoch = p_epoch
       AND status = 'CANCELLING' AND teardown_deadline_at < now();
  END IF;
  GET DIAGNOSTICS n = ROW_COUNT;
  RESET ROLE;
  RETURN n = 1;
EXCEPTION WHEN OTHERS THEN
  RESET ROLE;
  RAISE;
END
$$;

-- The sweep for one reason, in two steps: the system role finds, the tenant role moves each one found.
-- Returns the ids that were moved.
CREATE FUNCTION dbtest.sweep(p_reason text DEFAULT 'lease_expired') RETURNS uuid[] LANGUAGE plpgsql AS $$
DECLARE
  c record;
  swept uuid[] := '{}';
BEGIN
  FOR c IN SELECT * FROM dbtest.find_due_attempts(p_reason) LOOP
    IF dbtest.settle_due(p_reason, c.tenant_id, c.attempt_id, c.version, c.lease_epoch) THEN
      swept := swept || c.attempt_id;
    END IF;
  END LOOP;
  RETURN swept;
END
$$;

-- A READY stage run number r of job 1101, as the engine would leave it.
CREATE FUNCTION dbtest.mk_ready_run(r int) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE
  new_id uuid := dbtest.u(1700 + r);
BEGIN
  INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number) VALUES (dbtest.u(1), new_id, dbtest.u(1101), 'INTAKE', r);
  UPDATE stage_runs SET status = 'READY', version = version + 1 WHERE tenant_id = dbtest.u(1) AND id = new_id;
  RETURN new_id;
END
$$;

CREATE TEMP TABLE ctx (k text PRIMARY KEY, v uuid);

-- ---------------------------------------------------------------------------------------------
-- 1. A claim has exactly one winner. Run 1701.

DO $$
DECLARE
  a1 uuid;
BEGIN
  PERFORM dbtest.mk_ready_run(1);
  a1 := dbtest.claim('worker-a');
  INSERT INTO ctx VALUES ('a1', a1);
  PERFORM dbtest.expect_true('the first claimer, running as the application role, gets an attempt', a1 IS NOT NULL);
  PERFORM dbtest.expect_true('a second claimer finds nothing to claim', dbtest.claim('worker-b') IS NULL);
  PERFORM dbtest.expect_eq('the stage run is RUNNING at lease epoch 1 with one attempt',
    (SELECT s.status || ':' || s.lease_epoch || ':' || (SELECT count(*) FROM attempts WHERE stage_run_id = s.id) FROM stage_runs s WHERE s.id = dbtest.u(1701)), 'RUNNING:1:1');
  PERFORM dbtest.expect_eq('the attempt holds epoch 1, is owned by worker-a and is STARTING',
    (SELECT lease_epoch || ':' || lease_owner || ':' || status FROM attempts WHERE id = a1), '1:worker-a:STARTING');
END
$$;

-- The database refuses a second live attempt for the run, whatever the claim code did.
DO $$
BEGIN
  PERFORM dbtest.expect_error('a second live attempt for the same stage run violates the one-active-attempt index',
    format($q$INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
              VALUES (%L, gen_random_uuid(), %L, %L, 2, 'worker-b', 1, now() + interval '30 seconds', now() + interval '1 hour')$q$,
           dbtest.u(1), dbtest.u(1101), dbtest.u(1701)), '23505', 'factory_app', 'attempts_one_active_per_stage_run');
END
$$;

-- The claim crosses tenants: the system role finds a READY run of tenant 2, and the attempt is written
-- under the setting for tenant 2, so it belongs to tenant 2 and tenant 1's session cannot see it.
DO $$
DECLARE
  a uuid;
BEGIN
  PERFORM dbtest.mk_job(2, 1);
  PERFORM dbtest.set_status('jobs', 2, dbtest.u(2101), 'ACTIVE');
  INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number) VALUES (dbtest.u(2), dbtest.u(2701), dbtest.u(2101), 'INTAKE', 1);
  PERFORM dbtest.set_status('stage_runs', 2, dbtest.u(2701), 'READY');
  a := dbtest.claim('worker-t2');
  PERFORM dbtest.expect_true('the system role found the READY run of tenant 2 and the claim wrote its attempt', a IS NOT NULL);
  PERFORM dbtest.expect_eq('the attempt belongs to tenant 2, at lease epoch 1', (SELECT tenant_id::text || ':' || lease_epoch FROM attempts WHERE id = a), dbtest.u(2)::text || ':1');
  PERFORM dbtest.expect_eq('a tenant-1 session cannot see the attempt of tenant 2', dbtest.run_as(format('SELECT 1 FROM attempts WHERE id = %L', a), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_eq('and a tenant-2 session can', dbtest.run_as(format('SELECT 1 FROM attempts WHERE id = %L', a), 'factory_app', 2), 'rows=1');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. An attempt holds the run's current lease epoch, is numbered in order, and respects the limit.

DO $$
BEGIN
  -- Run 1702: RUNNING at epoch 1 with no attempt yet, as the engine would leave it between statements.
  PERFORM dbtest.mk_ready_run(2);
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1702), 'RUNNING', ', lease_epoch = lease_epoch + 1');
  PERFORM dbtest.expect_error('an attempt at epoch 7 for a run at epoch 1 is rejected when the constraint is checked',
    format($q$SET CONSTRAINTS attempts_epoch_check IMMEDIATE;
              INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
              VALUES (%L, gen_random_uuid(), %L, %L, 1, 'worker-a', 7, now() + interval '30 seconds', now() + interval '1 hour')$q$,
           dbtest.u(1), dbtest.u(1101), dbtest.u(1702)), '23514', 'factory_app', 'attempts_live_attempt_has_current_epoch');
  PERFORM dbtest.expect_ok('an attempt at the run''s current epoch is accepted (the epoch check passes)',
    format($q$SET CONSTRAINTS attempts_epoch_check IMMEDIATE;
              INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
              VALUES (%L, gen_random_uuid(), %L, %L, 1, 'worker-a', 1, now() + interval '30 seconds', now() + interval '1 hour')$q$,
           dbtest.u(1), dbtest.u(1101), dbtest.u(1702)), 'factory_app');
  PERFORM dbtest.expect_error('attempts are numbered in order: number 2 before number 1 is rejected',
    format($q$INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
              VALUES (%L, gen_random_uuid(), %L, %L, 2, 'worker-a', 1, now() + interval '30 seconds', now() + interval '1 hour')$q$,
           dbtest.u(1), dbtest.u(1101), dbtest.u(1702)), '23514', 'factory_app', 'attempts_numbered_in_sequence');

  -- Run 1703: a limit of one attempt.
  PERFORM dbtest.mk_ready_run(3);
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1703), 'RUNNING', ', lease_epoch = lease_epoch + 1, max_attempts = 1');
  INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
    VALUES (dbtest.u(1), dbtest.u(1393), dbtest.u(1101), dbtest.u(1703), 1, 'worker-a', 1, now() + interval '30 seconds', now() + interval '1 hour');
  PERFORM dbtest.set_status('attempts', 1, dbtest.u(1393), 'FAILED', ', failure_class = ''TOOL_ERROR'', ended_at = now()');
  PERFORM dbtest.expect_error('a run that allows one attempt refuses a second even after the first failed (INV-10)',
    format($q$INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
              VALUES (%L, gen_random_uuid(), %L, %L, 2, 'worker-a', 1, now() + interval '30 seconds', now() + interval '1 hour')$q$,
           dbtest.u(1), dbtest.u(1101), dbtest.u(1703)), '23514', 'factory_app', 'attempts_within_stage_run_limit');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. A lease is bounded by the database clock, not by the caller's.

DO $$
BEGIN
  PERFORM dbtest.mk_ready_run(4);
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1704), 'RUNNING', ', lease_epoch = lease_epoch + 1');
  PERFORM dbtest.expect_error('a new attempt with a lease two hours ahead of the database time is rejected',
    format($q$INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
              VALUES (%L, gen_random_uuid(), %L, %L, 1, 'worker-a', 1, now() + interval '2 hours', now() + interval '3 hours')$q$,
           dbtest.u(1), dbtest.u(1101), dbtest.u(1704)), '23514', 'factory_app', 'attempts_lease_within_bound');
  PERFORM dbtest.expect_error('a renewal written with a skewed worker clock far in the future is rejected',
    format($q$UPDATE attempts SET lease_expires_at = now() + interval '5 hours', version = version + 1 WHERE id = %L$q$, (SELECT v FROM ctx WHERE k = 'a1')),
    '23514', 'factory_app', 'attempts_lease_within_bound');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. A renewal is fenced by tenant, attempt, owner, epoch and the database clock. Attempt A1 belongs
-- to worker-a at epoch 1 in tenant 1.

DO $$
DECLARE
  a1 uuid := (SELECT v FROM ctx WHERE k = 'a1');
BEGIN
  PERFORM dbtest.expect_true('a renewal with the right owner and epoch succeeds', dbtest.renew(dbtest.u(1), a1, 'worker-a', 1));
  PERFORM dbtest.expect_true('NT-LSE-02: a renewal with the wrong owner is refused', NOT dbtest.renew(dbtest.u(1), a1, 'worker-x', 1));
  PERFORM dbtest.expect_true('NT-LSE-02: a renewal with the wrong tenant is refused', NOT dbtest.renew(dbtest.u(2), a1, 'worker-a', 1));
  PERFORM dbtest.expect_true('a renewal with the wrong epoch is refused', NOT dbtest.renew(dbtest.u(1), a1, 'worker-a', 2));
  PERFORM dbtest.expect_true('a renewal of an attempt that does not exist is refused', NOT dbtest.renew(dbtest.u(1), dbtest.u(999999), 'worker-a', 1));
  -- Let the lease lapse by the database clock.
  UPDATE attempts SET lease_expires_at = now() - interval '1 second', version = version + 1 WHERE id = a1;
  PERFORM dbtest.expect_true('a renewal after the lease expired by the database clock is refused', NOT dbtest.renew(dbtest.u(1), a1, 'worker-a', 1));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 5. The sweeper takes only expired leases, judged by now(); a retry honours its back-off; the next
-- claim runs at epoch 2 (NT-LSE-01).

DO $$
DECLARE
  a1 uuid := (SELECT v FROM ctx WHERE k = 'a1');
  swept uuid[];
  a2 uuid;
BEGIN
  -- A live lease on another run must survive the sweep: claim run 1705 now, with a fresh lease.
  PERFORM dbtest.mk_ready_run(5);
  PERFORM dbtest.expect_true('worker-c claims run 1705', dbtest.claim('worker-c') IS NOT NULL);

  -- Only A1 has an expired lease. The sweep finds it as the system role and marks it lost as the tenant role.
  swept := dbtest.sweep();
  PERFORM dbtest.expect_eq('the sweep (system role finds, tenant role marks) took exactly the expired attempt', swept, ARRAY[a1]);
  PERFORM dbtest.expect_eq('the live lease of worker-c was left alone',
    (SELECT count(*) FROM attempts WHERE status = 'STARTING' AND lease_owner = 'worker-c' AND lease_expires_at > now()), 1::bigint);

  -- Schedule the retry with a back-off (S05), as the engine would.
  UPDATE stage_runs SET status = 'READY', not_before = now() + interval '1 hour', version = version + 1 WHERE tenant_id = dbtest.u(1) AND id = dbtest.u(1701);
  PERFORM dbtest.expect_true('during the back-off nobody can claim the run', dbtest.claim('worker-b') IS NULL);
  UPDATE stage_runs SET not_before = now() - interval '1 second', version = version + 1 WHERE tenant_id = dbtest.u(1) AND id = dbtest.u(1701);
  a2 := dbtest.claim('worker-b');
  INSERT INTO ctx VALUES ('a2', a2);
  PERFORM dbtest.expect_true('after the back-off worker-b claims the run', a2 IS NOT NULL);
  PERFORM dbtest.expect_eq('the new attempt is number 2 at lease epoch 2',
    (SELECT attempt_number || ':' || lease_epoch || ':' || lease_owner FROM attempts WHERE id = a2), '2:2:worker-b');
  PERFORM dbtest.expect_eq('the run is now at epoch 2', (SELECT lease_epoch FROM stage_runs WHERE id = dbtest.u(1701)), 2::bigint);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 6. The zombie: worker-a holds epoch 1, lost the lease, and wakes up after worker-b took over at epoch 2.

DO $$
DECLARE
  a1 uuid := (SELECT v FROM ctx WHERE k = 'a1');
  a2 uuid := (SELECT v FROM ctx WHERE k = 'a2');
  n bigint;
BEGIN
  PERFORM dbtest.expect_true('NT-LSE-01: the zombie cannot renew its old attempt', NOT dbtest.renew(dbtest.u(1), a1, 'worker-a', 1));
  PERFORM dbtest.expect_true('NT-LSE-01: the zombie cannot renew the new attempt with its old epoch', NOT dbtest.renew(dbtest.u(1), a2, 'worker-a', 1));
  PERFORM dbtest.expect_true('NT-LSE-01: the zombie cannot renew the new attempt as the new owner either', NOT dbtest.renew(dbtest.u(1), a2, 'worker-a', 2));
  PERFORM dbtest.expect_error('NT-LSE-01: the zombie cannot report success on its old attempt',
    format($q$UPDATE attempts SET status = 'SUCCEEDED', output_sha256 = %L, ended_at = now(), version = version + 1 WHERE id = %L$q$, dbtest.sha('late'), a1), '23514', 'factory_app');
  PERFORM dbtest.expect_error('NT-LSE-01: the zombie cannot report success even with a WHERE clause that forgot the status',
    format($q$UPDATE attempts SET status = 'RUNNING', version = version + 1 WHERE id = %L$q$, a1), '23514', 'factory_app');
  PERFORM dbtest.expect_error('a stale claimer cannot start a second live attempt at the old epoch',
    format($q$INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
              VALUES (%L, gen_random_uuid(), %L, %L, 3, 'worker-a', 1, now() + interval '30 seconds', now() + interval '1 hour')$q$,
           dbtest.u(1), dbtest.u(1101), dbtest.u(1701)), '23505', 'factory_app', 'attempts_one_active_per_stage_run');

  -- A compare-and-swap on the stage run with the version the zombie last saw changes no row.
  PERFORM dbtest.become('factory_app');
  UPDATE stage_runs SET status = 'GATING', version = version + 1 WHERE tenant_id = dbtest.u(1) AND id = dbtest.u(1701) AND version = 2;
  GET DIAGNOSTICS n = ROW_COUNT;
  RESET ROLE;
  PERFORM dbtest.expect_eq('NT-LSE-01: a stage run update with a stale version changes zero rows (StoreError::Conflict)', n, 0::bigint);

  PERFORM dbtest.expect_true('worker-b, the real owner at epoch 2, can renew', dbtest.renew(dbtest.u(1), a2, 'worker-b', 2));
  PERFORM dbtest.expect_eq('the history shows one lost attempt at epoch 1 and one live attempt at epoch 2',
    (SELECT string_agg(attempt_number || ':' || status || ':' || lease_epoch, ' ' ORDER BY attempt_number) FROM attempts WHERE stage_run_id = dbtest.u(1701)),
    '1:LEASE_LOST:1 2:STARTING:2');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 7. start_attempt: every outcome the port names (ADR 0014, rule R2). A run is found with its version; the
-- caller passes that version back.

CREATE FUNCTION dbtest.version_of(p_run uuid) RETURNS bigint LANGUAGE sql AS $$
  SELECT version FROM stage_runs WHERE id = p_run
$$;

-- The attempt a run has, as 'number:epoch:status', for a short comparison.
CREATE FUNCTION dbtest.attempts_of(p_run uuid) RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(attempt_number || ':' || lease_epoch || ':' || status, ' ' ORDER BY attempt_number), '-') FROM attempts WHERE stage_run_id = p_run
$$;

DO $$
DECLARE
  r record;
  run uuid;
BEGIN
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), dbtest.u(999999), 1, 'worker-s');
  PERFORM dbtest.expect_eq('start_attempt: a stage run that does not exist is not_found', r.outcome, 'not_found');

  run := dbtest.mk_ready_run(10);
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(2), run, dbtest.version_of(run), 'worker-s');
  PERFORM dbtest.expect_eq('start_attempt: the run of another tenant is not_found, the answer for a run that does not exist', r.outcome, 'not_found');
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), run, dbtest.version_of(run) - 1, 'worker-s');
  PERFORM dbtest.expect_eq('start_attempt: a version that is no longer current is a conflict', r.outcome, 'conflict');

  UPDATE stage_runs SET not_before = now() + interval '10 minutes', version = version + 1 WHERE id = run;
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), run, dbtest.version_of(run), 'worker-s');
  PERFORM dbtest.expect_eq('start_attempt: a run whose not_before is in the future is backing_off', r.outcome, 'backing_off');
  PERFORM dbtest.expect_eq('and the run is untouched (still READY at epoch 0, no attempt)',
    (SELECT status || ':' || lease_epoch FROM stage_runs WHERE id = run) || ' ' || dbtest.attempts_of(run), 'READY:0 -');
  PERFORM dbtest.expect_true('and find_claim_candidates does not list it',
    NOT EXISTS (SELECT 1 FROM dbtest.find_candidates(1000) c WHERE c.stage_run_id = run));

  -- A run of a job that is not ACTIVE: a candidate that went stale between the two steps.
  PERFORM dbtest.mk_job(1, 2);
  PERFORM dbtest.set_status('jobs', 1, dbtest.u(1102), 'ACTIVE');
  INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number) VALUES (dbtest.u(1), dbtest.u(1750), dbtest.u(1102), 'INTAKE', 1);
  PERFORM dbtest.set_status('stage_runs', 1, dbtest.u(1750), 'READY');
  PERFORM dbtest.expect_true('find_claim_candidates lists a READY run of an ACTIVE job',
    EXISTS (SELECT 1 FROM dbtest.find_candidates(1000) c WHERE c.stage_run_id = dbtest.u(1750)));
  PERFORM dbtest.set_status('jobs', 1, dbtest.u(1102), 'PAUSED');
  PERFORM dbtest.expect_true('and does not list it once the job is PAUSED',
    NOT EXISTS (SELECT 1 FROM dbtest.find_candidates(1000) c WHERE c.stage_run_id = dbtest.u(1750)));
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), dbtest.u(1750), dbtest.version_of(dbtest.u(1750)), 'worker-s');
  PERFORM dbtest.expect_eq('start_attempt: a run of a job that is not ACTIVE is job_not_active', r.outcome, 'job_not_active');
  PERFORM dbtest.expect_eq('and creates nothing', dbtest.attempts_of(dbtest.u(1750)), '-');

  -- The largest epoch. Set with the triggers off (a superuser setting that reaches this block only).
  run := dbtest.mk_ready_run(11);
  SET LOCAL session_replication_role = replica;
  UPDATE stage_runs SET lease_epoch = 9223372036854775807, version = version + 1 WHERE id = run;
  SET LOCAL session_replication_role = origin;
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), run, dbtest.version_of(run), 'worker-s');
  PERFORM dbtest.expect_eq('start_attempt: a run at the largest epoch is epoch_exhausted (LeaseEpoch::MAX)', r.outcome, 'epoch_exhausted');
  PERFORM dbtest.expect_error('and the raw increment fails with bigint out of range, so the epoch can never wrap',
    format($q$UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, version = version + 1 WHERE id = %L$q$, run), '22003', 'factory_app');
  PERFORM dbtest.expect_eq('nothing was partly applied', (SELECT status || ':' || lease_epoch FROM stage_runs WHERE id = run) || ' ' || dbtest.attempts_of(run), 'READY:9223372036854775807 -');

  -- The attempt limit: one attempt allowed and one used.
  run := dbtest.mk_ready_run(12);
  PERFORM dbtest.set_status('stage_runs', 1, run, 'RUNNING', ', lease_epoch = lease_epoch + 1, max_attempts = 1');
  INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
    VALUES (dbtest.u(1), dbtest.u(5012), dbtest.u(1101), run, 1, 'worker-s', 1, now() + interval '30 seconds', now() + interval '1 hour');
  PERFORM dbtest.set_status('attempts', 1, dbtest.u(5012), 'FAILED', ', failure_class = ''TOOL_ERROR'', ended_at = now()');
  PERFORM dbtest.set_status('stage_runs', 1, run, 'READY');
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), run, dbtest.version_of(run), 'worker-s');
  PERFORM dbtest.expect_eq('start_attempt: a run that has used its attempts is attempt_limit (INV-10)', r.outcome, 'attempt_limit');

  -- The start itself.
  run := dbtest.mk_ready_run(13);
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), run, dbtest.version_of(run), 'worker-s');
  PERFORM dbtest.expect_eq('start_attempt: a READY run of an ACTIVE job at the version read is started', r.outcome, 'started');
  PERFORM dbtest.expect_eq('the run is RUNNING at epoch 1, with one STARTING attempt number 1 at epoch 1',
    (SELECT status || ':' || lease_epoch FROM stage_runs WHERE id = run) || ' ' || dbtest.attempts_of(run), 'RUNNING:1 1:1:STARTING');
  PERFORM dbtest.expect_eq('the lease and the deadline come from the database clock (now() plus 30 seconds and plus one hour)',
    (SELECT (lease_expires_at = now() + interval '30 seconds' AND deadline_at = now() + interval '1 hour')::text FROM attempts WHERE id = r.attempt_id), 'true');
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), run, dbtest.version_of(run) - 1, 'worker-t');
  PERFORM dbtest.expect_eq('a second start_attempt for the version it started from is a conflict, not a second attempt', r.outcome, 'conflict');
  PERFORM dbtest.expect_eq('and the run still has one attempt', dbtest.attempts_of(run), '1:1:STARTING');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 8. The attempt limit counts the attempts since the last human answer (INV-10, G_RETRY_ALLOWED). One attempt
-- is allowed. After it fails and a person answers, one more is allowed; then the window is used up again.

DO $$
DECLARE
  r record;
  run uuid := dbtest.mk_ready_run(14);
  a1 uuid;
  a2 uuid;
BEGIN
  PERFORM dbtest.exec(format($q$UPDATE stage_runs SET max_attempts = 1, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), run), 'factory_app');
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), run, dbtest.version_of(run), 'worker-s');
  a1 := r.attempt_id;
  PERFORM dbtest.expect_eq('the first attempt of a run that allows one is started', r.outcome, 'started');
  -- S07: the attempt fails on its budget and the run waits for a person, in one transaction.
  PERFORM dbtest.exec(format($q$UPDATE attempts SET status = 'FAILED', failure_class = 'BUDGET_EXHAUSTED', ended_at = now(), version = version + 1 WHERE tenant_id = %1$L AND id = %2$L;
                               UPDATE stage_runs SET status = 'WAITING_FOR_HUMAN', version = version + 1 WHERE tenant_id = %1$L AND id = %3$L$q$, dbtest.u(1), a1, run), 'factory_app');
  PERFORM dbtest.expect_eq('the window starts at 0 before any answer', (SELECT attempts_before_last_answer FROM stage_runs WHERE id = run), 0);
  -- S13: the answer. The tenant role does not write attempts_before_last_answer; the database derives it.
  PERFORM dbtest.exec(format($q$UPDATE stage_runs SET status = 'READY', version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), run), 'factory_app');
  PERFORM dbtest.expect_eq('S13 (WAITING_FOR_HUMAN to READY) records that one attempt came before the answer', (SELECT attempts_before_last_answer FROM stage_runs WHERE id = run), 1);
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), run, dbtest.version_of(run), 'worker-s');
  a2 := r.attempt_id;
  PERFORM dbtest.expect_eq('after the answer one more attempt is allowed, and it is number 2 at epoch 2', r.outcome || ' ' || dbtest.attempts_of(run), 'started 1:1:FAILED 2:2:STARTING');
  PERFORM dbtest.exec(format($q$UPDATE attempts SET status = 'FAILED', failure_class = 'TOOL_ERROR', ended_at = now(), version = version + 1 WHERE tenant_id = %1$L AND id = %2$L;
                               UPDATE stage_runs SET status = 'READY', not_before = now(), version = version + 1 WHERE tenant_id = %1$L AND id = %3$L$q$, dbtest.u(1), a2, run), 'factory_app');
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), run, dbtest.version_of(run), 'worker-s');
  PERFORM dbtest.expect_eq('a third attempt without a new answer is attempt_limit again', r.outcome, 'attempt_limit');
  PERFORM dbtest.expect_error('the trigger agrees when the attempt is inserted directly (attempts_within_stage_run_limit)',
    format($q$INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
              VALUES (%L, gen_random_uuid(), %L, %L, 3, 'worker-s', 2, now() + interval '30 seconds', now() + interval '1 hour')$q$,
           dbtest.u(1), dbtest.u(1101), run), '23514', 'factory_app', 'attempts_within_stage_run_limit');
  PERFORM dbtest.expect_error('the tenant role cannot write the window (no column privilege)',
    format($q$UPDATE stage_runs SET attempts_before_last_answer = 0, version = version + 1 WHERE id = %L$q$, run), '42501', 'factory_app');
  PERFORM dbtest.expect_error('and nobody else can change it except through S13, not even the owner',
    format($q$UPDATE stage_runs SET status = 'CANCELLED', finished_at = now(), attempts_before_last_answer = 0, version = version + 1 WHERE id = %L$q$, run),
    '23514', NULL, 'stage_runs_answer_window_is_derived');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 9. A retry waits for no lease (S05). The failed attempt is terminal in the transaction that moves the run
-- back to READY; nothing else holds anything. The data refuses the other order of events at commit.

DO $$
DECLARE
  r record;
  run uuid := dbtest.mk_ready_run(15);
  a1 uuid;
  settle text := 'SET CONSTRAINTS stage_runs_live_attempt_check, attempts_live_attempt_check IMMEDIATE';
BEGIN
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), run, dbtest.version_of(run), 'worker-s');
  a1 := r.attempt_id;
  PERFORM dbtest.expect_error('S05 while the attempt is still live is refused at commit (a lease would be left behind)',
    format($q$UPDATE stage_runs SET status = 'READY', not_before = now() + interval '1 minute', version = version + 1 WHERE tenant_id = %L AND id = %L; %s$q$, dbtest.u(1), run, settle),
    '23514', 'factory_app', 'stage_runs_live_attempt_needs_running_run');
  PERFORM dbtest.expect_ok('S05 in the order run first, attempt second, is accepted once both are in the transaction',
    format($q$UPDATE stage_runs SET status = 'READY', not_before = now() + interval '1 minute', version = version + 1 WHERE tenant_id = %1$L AND id = %2$L;
              UPDATE attempts SET status = 'FAILED', failure_class = 'TOOL_ERROR', ended_at = now(), version = version + 1 WHERE tenant_id = %1$L AND id = %3$L; %4$s$q$, dbtest.u(1), run, a1, settle), 'factory_app');
  PERFORM dbtest.expect_ok('and in the order attempt first, run second',
    format($q$UPDATE attempts SET status = 'FAILED', failure_class = 'TOOL_ERROR', ended_at = now(), version = version + 1 WHERE tenant_id = %1$L AND id = %3$L;
              UPDATE stage_runs SET status = 'READY', not_before = now() + interval '1 minute', version = version + 1 WHERE tenant_id = %1$L AND id = %2$L; %4$s$q$, dbtest.u(1), run, a1, settle), 'factory_app');
  PERFORM dbtest.expect_error('a live attempt cannot be made for a run that is not RUNNING and not SUPERSEDED (here: a PENDING run)',
    format($q$INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number) VALUES (%1$L, %2$L, %3$L, 'INTAKE', 99);
              INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
              VALUES (%1$L, gen_random_uuid(), %3$L, %2$L, 1, 'worker-s', 1, now() + interval '30 seconds', now() + interval '1 hour'); %4$s$q$, dbtest.u(1), dbtest.u(1799), dbtest.u(1101), settle),
    '23514', 'factory_app', 'stage_runs_live_attempt_needs_running_run');

  -- For real: S05 with no back-off, the old attempt's lease still ahead of the clock. The retry starts at once.
  PERFORM dbtest.exec(format($q$UPDATE attempts SET status = 'FAILED', failure_class = 'TOOL_ERROR', ended_at = now(), version = version + 1 WHERE tenant_id = %1$L AND id = %3$L;
                               UPDATE stage_runs SET status = 'READY', not_before = now(), version = version + 1 WHERE tenant_id = %1$L AND id = %2$L$q$, dbtest.u(1), run, a1), 'factory_app');
  PERFORM dbtest.expect_true('the failed attempt still has a lease that has not lapsed', (SELECT lease_expires_at > now() FROM attempts WHERE id = a1));
  PERFORM dbtest.expect_true('and the retry is found as a candidate straight away',
    EXISTS (SELECT 1 FROM dbtest.find_candidates(1000) c WHERE c.stage_run_id = run));
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), run, dbtest.version_of(run), 'worker-r');
  PERFORM dbtest.expect_eq('and is started: attempt 2 at epoch 2 while attempt 1 is FAILED at epoch 1, with no wait for any lease',
    r.outcome || ' ' || dbtest.attempts_of(run), 'started 1:1:FAILED 2:2:STARTING');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 10. postpone_stage_run: not_before moves while the run stays READY, and only then.

DO $$
DECLARE
  r record;
  run uuid := dbtest.mk_ready_run(16);
  running uuid := dbtest.u(1715);   -- run 15, RUNNING with attempt 2 from section 9
BEGIN
  PERFORM dbtest.expect_eq('postpone: a READY run is postponed by the tenant role in one compare and swap',
    dbtest.run_as(format($q$UPDATE stage_runs SET not_before = now() + interval '5 minutes', version = version + 1 WHERE tenant_id = %L AND id = %L AND version = %s AND status = 'READY'$q$, dbtest.u(1), run, dbtest.version_of(run)), 'factory_app', 1),
    'rows=1');
  PERFORM dbtest.exec(format($q$UPDATE stage_runs SET not_before = now() + interval '5 minutes', version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), run), 'factory_app');
  PERFORM dbtest.expect_true('a postponed run is not a candidate', NOT EXISTS (SELECT 1 FROM dbtest.find_candidates(1000) c WHERE c.stage_run_id = run));
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), run, dbtest.version_of(run), 'worker-s');
  PERFORM dbtest.expect_eq('and start_attempt says backing_off', r.outcome, 'backing_off');
  PERFORM dbtest.expect_eq('the status did not change and the version rose once', (SELECT status || ':' || version FROM stage_runs WHERE id = run), 'READY:3');

  PERFORM dbtest.expect_error('not_before cannot change on a RUNNING run',
    format($q$UPDATE stage_runs SET not_before = now() + interval '5 minutes', version = version + 1 WHERE id = %L$q$, running),
    '23514', 'factory_app', 'stage_runs_not_before_only_when_ready');
  PERFORM dbtest.expect_error('nor while the run leaves READY (a back-off belongs to a run that is READY)',
    format($q$UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, not_before = now() + interval '1 hour', version = version + 1 WHERE id = %L$q$, dbtest.u(1710)),
    '23514', 'factory_app', 'stage_runs_not_before_only_when_ready');
  PERFORM dbtest.expect_error('a READY run cannot change anything else without a status move (here: the gate outcome)',
    format($q$UPDATE stage_runs SET gate_outcome = 'FAILED', version = version + 1 WHERE id = %L$q$, run),
    '23514', 'factory_app', 'stage_runs_update_is_a_move_or_a_postponement');
  PERFORM dbtest.expect_ok('a raised budget (max_attempts) is still allowed on a READY run',
    format($q$UPDATE stage_runs SET max_attempts = 5, version = version + 1 WHERE id = %L$q$, run), 'factory_app');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 11. find_due_attempts: lease, deadline and teardown. The attempts are inserted by the owner with a created_at
-- in the past, so that a deadline in the past is still after the creation time. Runs 20 to 25.

CREATE FUNCTION dbtest.mk_attempt(p_run int, p_lease interval, p_deadline interval, p_teardown interval DEFAULT NULL) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE
  run uuid := dbtest.mk_ready_run(p_run);
  att uuid := dbtest.u(5000 + p_run);
BEGIN
  PERFORM dbtest.set_status('stage_runs', 1, run, 'RUNNING', ', lease_epoch = lease_epoch + 1');
  INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at, created_at)
    VALUES (dbtest.u(1), att, dbtest.u(1101), run, 1, 'worker-q', 1, now() + p_lease, now() + p_deadline, now() - interval '3 hours');
  IF p_teardown IS NOT NULL THEN
    PERFORM dbtest.set_status('attempts', 1, att, 'CANCELLING', ', teardown_deadline_at = now() + ' || quote_literal(p_teardown::text) || '::interval');
  END IF;
  RETURN att;
END
$$;

DO $$
DECLARE
  lease_gone uuid := dbtest.mk_attempt(20, interval '-1 minute', interval '1 hour');
  deadline_gone uuid := dbtest.mk_attempt(21, interval '10 minutes', interval '-1 minute');
  teardown_gone uuid := dbtest.mk_attempt(22, interval '10 minutes', interval '1 hour', interval '-1 minute');
  both_gone uuid := dbtest.mk_attempt(23, interval '-2 minutes', interval '-1 minute');
  all_live uuid := dbtest.mk_attempt(24, interval '10 minutes', interval '1 hour');
  cancelling_live uuid := dbtest.mk_attempt(25, interval '-5 minutes', interval '1 hour', interval '1 hour');
  ours uuid[] := ARRAY[dbtest.u(5020), dbtest.u(5021), dbtest.u(5022), dbtest.u(5023), dbtest.u(5024), dbtest.u(5025)];
  found uuid[];
  swept uuid[];
BEGIN
  SELECT coalesce(array_agg(d.attempt_id ORDER BY d.attempt_id), '{}') INTO found FROM dbtest.find_due_attempts('lease_expired') d WHERE d.attempt_id = ANY (ours);
  PERFORM dbtest.expect_eq('lease_expired: finds the attempt whose lease lapsed and the one whose lease and deadline both lapsed, and no other',
    found, ARRAY[lease_gone, both_gone]);
  PERFORM dbtest.expect_true('lease_expired does not list a CANCELLING attempt with a lapsed lease: that one is the teardown deadline''s',
    NOT (cancelling_live = ANY (found)));
  SELECT coalesce(array_agg(d.attempt_id ORDER BY d.attempt_id), '{}') INTO found FROM dbtest.find_due_attempts('deadline_passed') d WHERE d.attempt_id = ANY (ours);
  PERFORM dbtest.expect_eq('deadline_passed: finds the attempt past its deadline with a live lease, and the one past both', found, ARRAY[deadline_gone, both_gone]);
  SELECT coalesce(array_agg(d.attempt_id ORDER BY d.attempt_id), '{}') INTO found FROM dbtest.find_due_attempts('teardown_deadline_passed') d WHERE d.attempt_id = ANY (ours);
  PERFORM dbtest.expect_eq('teardown_deadline_passed: finds only the CANCELLING attempt past its teardown deadline', found, ARRAY[teardown_gone]);
  PERFORM dbtest.expect_eq('find_due_attempts returns the epoch and the version the move must carry',
    (SELECT d.lease_epoch || ':' || (d.version = (SELECT version FROM attempts WHERE id = lease_gone))::text FROM dbtest.find_due_attempts('lease_expired') d WHERE d.attempt_id = lease_gone), '1:true');

  PERFORM dbtest.expect_true('a move with a stale epoch changes nothing (A07 fenced by the epoch the sweeper read)',
    NOT dbtest.settle_due('lease_expired', dbtest.u(1), lease_gone, (SELECT version FROM attempts WHERE id = lease_gone), 2));
  PERFORM dbtest.expect_true('a move with a stale version changes nothing',
    NOT dbtest.settle_due('lease_expired', dbtest.u(1), lease_gone, (SELECT version FROM attempts WHERE id = lease_gone) - 1, 1));
  PERFORM dbtest.expect_error('the system role finds but cannot write: an UPDATE of an attempt is refused',
    format($q$UPDATE attempts SET status = 'LEASE_LOST', ended_at = now(), version = version + 1 WHERE id = %L$q$, lease_gone), '42501', 'factory_system');

  swept := dbtest.sweep('lease_expired');
  PERFORM dbtest.expect_eq('the tenant role moved the two attempts with a lapsed lease to LEASE_LOST (A07)',
    (SELECT array_agg(x ORDER BY x) FROM unnest(swept) x WHERE x = ANY (ours)), ARRAY[lease_gone, both_gone]);
  swept := dbtest.sweep('deadline_passed');
  PERFORM dbtest.expect_eq('the sweep for deadlines then finds only the one the lease sweep left: it moved to TIMED_OUT (A06)',
    (SELECT array_agg(x ORDER BY x) FROM unnest(swept) x WHERE x = ANY (ours)), ARRAY[deadline_gone]);
  swept := dbtest.sweep('teardown_deadline_passed');
  PERFORM dbtest.expect_eq('and the teardown sweep moved the overdue CANCELLING attempt to CANCELLED and flagged its sandbox as leaked (A10)',
    (SELECT array_agg(x ORDER BY x) FROM unnest(swept) x WHERE x = ANY (ours)), ARRAY[teardown_gone]);
  PERFORM dbtest.expect_eq('the end states are LEASE_LOST, TIMED_OUT, CANCELLED, LEASE_LOST, and the two live ones untouched',
    (SELECT string_agg(status, ' ' ORDER BY id) FROM attempts WHERE id = ANY (ours)), 'LEASE_LOST TIMED_OUT CANCELLED LEASE_LOST STARTING CANCELLING');
  PERFORM dbtest.expect_eq('only the force-killed sandbox is flagged as leaked', (SELECT string_agg(id::text, ',') FROM attempts WHERE id = ANY (ours) AND sandbox_leaked), teardown_gone::text);
  PERFORM dbtest.expect_eq('a second sweep finds nothing of ours', coalesce(array_length((SELECT array_agg(d.attempt_id) FROM (
      SELECT attempt_id FROM dbtest.find_due_attempts('lease_expired') UNION ALL SELECT attempt_id FROM dbtest.find_due_attempts('deadline_passed')
      UNION ALL SELECT attempt_id FROM dbtest.find_due_attempts('teardown_deadline_passed')) d WHERE d.attempt_id = ANY (ours)), 1), 0), 0);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 12. Heartbeat on a CANCELLING attempt (AttemptOps::heartbeat): live, so it renews while the lease has not lapsed,
-- and the status it reads back tells the worker to tear down. A lapsed lease is the sweeper's.

DO $$
DECLARE
  live uuid := dbtest.mk_attempt(26, interval '10 minutes', interval '1 hour', interval '1 hour');
  lapsed uuid := dbtest.u(5025);   -- CANCELLING with a lapsed lease, from section 11
BEGIN
  PERFORM dbtest.expect_true('a heartbeat on a CANCELLING attempt whose lease is live renews it', dbtest.renew(dbtest.u(1), live, 'worker-q', 1));
  PERFORM dbtest.expect_eq('and the attempt reads back as CANCELLING', (SELECT status FROM attempts WHERE id = live), 'CANCELLING');
  PERFORM dbtest.expect_true('a heartbeat after the lease lapsed cannot revive it, whatever the status', NOT dbtest.renew(dbtest.u(1), lapsed, 'worker-q', 1));
  PERFORM dbtest.expect_true('a heartbeat on a finished attempt changes nothing', NOT dbtest.renew(dbtest.u(1), dbtest.u(5020), 'worker-q', 1));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 13. record_sandbox: the facts about a sandbox are written in any status, including after the attempt ended,
-- and only move forward.

DO $$
DECLARE
  done uuid := dbtest.u(5020);   -- LEASE_LOST, from section 11
  w text := format($q$UPDATE attempts SET sandbox_id = %%L, sandbox_leaked = %%L, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), done);
BEGIN
  PERFORM dbtest.exec(format(w, 'sbx-one', 'f'), 'factory_app');
  PERFORM dbtest.expect_eq('the sandbox of a LEASE_LOST attempt can be recorded afterwards', (SELECT sandbox_id || ':' || sandbox_leaked FROM attempts WHERE id = done), 'sbx-one:false');
  PERFORM dbtest.expect_ok('the same facts again are a repeat, not an error', format(w, 'sbx-one', 'f'), 'factory_app');
  PERFORM dbtest.exec(format(w, 'sbx-one', 't'), 'factory_app');
  PERFORM dbtest.expect_eq('leaked goes from false to true', (SELECT sandbox_leaked::text FROM attempts WHERE id = done), 'true');
  PERFORM dbtest.expect_error('leaked cannot go back to false', format(w, 'sbx-one', 'f'), '23514', 'factory_app', 'attempts_sandbox_leaked_only_rises');
  PERFORM dbtest.expect_error('the sandbox id cannot change once recorded', format(w, 'sbx-two', 't'), '23514', 'factory_app', 'attempts_sandbox_id_is_fixed');
  PERFORM dbtest.expect_error('and nothing else of a finished attempt can change (here: the failure class)',
    format($q$UPDATE attempts SET failure_class = 'INTERNAL', version = version + 1 WHERE id = %L$q$, done), '23514', 'factory_app', 'attempts_terminal_is_immutable');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 14. S21 and S22 (ADR 0014, decision 8).
--   S21 RUNNING -> BLOCKED: the attempt ends FAILED (SANDBOX_ERROR or TOOL_ERROR) in the same transaction, and
--       the run records the BLOCKED outcome. Nothing retries.
--   S22 READY -> WAITING_FOR_HUMAN: no attempt is created; the answer (S13) moves the run back to READY.

DO $$
DECLARE
  r record;
  blocked uuid := dbtest.mk_ready_run(30);
  asked uuid := dbtest.mk_ready_run(31);
  a uuid;
  settle text := 'SET CONSTRAINTS stage_runs_live_attempt_check, attempts_live_attempt_check IMMEDIATE';
BEGIN
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), blocked, dbtest.version_of(blocked), 'worker-s');
  a := r.attempt_id;
  PERFORM dbtest.expect_error('S21 without ending the attempt in the same transaction is refused at commit',
    format($q$UPDATE stage_runs SET status = 'BLOCKED', gate_outcome = 'BLOCKED', version = version + 1 WHERE tenant_id = %L AND id = %L; %s$q$, dbtest.u(1), blocked, settle),
    '23514', 'factory_app', 'stage_runs_live_attempt_needs_running_run');
  PERFORM dbtest.exec(format($q$UPDATE attempts SET status = 'FAILED', failure_class = 'SANDBOX_ERROR', ended_at = now(), version = version + 1 WHERE tenant_id = %1$L AND id = %3$L;
                               UPDATE stage_runs SET status = 'BLOCKED', gate_outcome = 'BLOCKED', version = version + 1 WHERE tenant_id = %1$L AND id = %2$L; %4$s$q$, dbtest.u(1), blocked, a, settle), 'factory_app');
  PERFORM dbtest.expect_eq('S21: the attempt is FAILED and the run is BLOCKED with the BLOCKED outcome, in one transaction',
    (SELECT status || ':' || gate_outcome FROM stage_runs WHERE id = blocked) || ' ' || dbtest.attempts_of(blocked), 'BLOCKED:BLOCKED 1:1:FAILED');
  PERFORM dbtest.expect_true('a BLOCKED run is not a candidate and has no lease to wait for',
    NOT EXISTS (SELECT 1 FROM dbtest.find_candidates(1000) c WHERE c.stage_run_id = blocked));

  PERFORM dbtest.exec(format($q$UPDATE stage_runs SET status = 'WAITING_FOR_HUMAN', version = version + 1 WHERE tenant_id = %L AND id = %L AND status = 'READY'$q$, dbtest.u(1), asked), 'factory_app');
  PERFORM dbtest.expect_eq('S22: a READY run moves to WAITING_FOR_HUMAN with no attempt', (SELECT status FROM stage_runs WHERE id = asked) || ' ' || dbtest.attempts_of(asked), 'WAITING_FOR_HUMAN -');
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), asked, dbtest.version_of(asked), 'worker-s');
  PERFORM dbtest.expect_eq('and nothing can start it while it waits (conflict: it is not READY)', r.outcome, 'conflict');
  PERFORM dbtest.exec(format($q$UPDATE stage_runs SET status = 'READY', version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), asked), 'factory_app');
  SELECT * INTO r FROM dbtest.start_attempt(dbtest.u(1), asked, dbtest.version_of(asked), 'worker-s');
  PERFORM dbtest.expect_eq('after the answer (S13) the run starts as any READY run, as attempt 1 at epoch 1', r.outcome || ' ' || dbtest.attempts_of(asked), 'started 1:1:STARTING');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 14. A lease renewal is a heap-only (HOT) update (work package s1-database-review, migration 19).
-- A heartbeat changes lease_expires_at, last_heartbeat_at and version, and nothing else. If an index is keyed on one of
-- those columns the update cannot be heap-only: PostgreSQL then writes a new entry to every index of the table for every
-- renewal and leaves a dead one behind in each. Measured on 90 seconds of heartbeats on 600 live attempts: 0.01 percent
-- heap-only with the index `attempts_lease_expiry_idx`, 99.9 percent without it (docs/database/performance.md). The
-- counter read here is the transaction's own, so the check does not wait for the statistics collector.
DO $$
DECLARE
  att uuid := dbtest.mk_attempt(41, interval '10 minutes', interval '1 hour');
  before bigint := pg_stat_get_xact_tuples_hot_updated('attempts'::regclass);
BEGIN
  PERFORM dbtest.expect_true('a renewal of a live lease succeeds', dbtest.renew(dbtest.u(1), att, 'worker-q', 1));
  PERFORM dbtest.expect_eq('and it is a heap-only update: no index is keyed on a column that a renewal changes',
    pg_stat_get_xact_tuples_hot_updated('attempts'::regclass) - before, 1::bigint);
END
$$;
