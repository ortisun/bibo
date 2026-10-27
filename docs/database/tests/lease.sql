-- Suite: lease
-- Proves the lease and claim rules (ADR 0001 and 0007; invariant INV-05; threat T-25; NT-LSE-01 and
-- NT-LSE-02 at the database level): a claim has one winner, an attempt holds the current epoch, a
-- zombie worker's writes are rejected, a forged renewal changes nothing, a retry back-off is honoured,
-- and lease time is judged by the database clock. The concurrent races run from scripts/db-test.sh
-- after this file.
--
-- Since ADR 0012 the claim and the sweep are two steps with two roles. The system role FINDS work across
-- tenants (SELECT ... FOR NO KEY UPDATE SKIP LOCKED over the columns it may read) and returns identifiers.
-- The tenant role then makes the change for the tenant it found: a compare and swap on version, the
-- lease epoch raised by one, the attempt inserted. dbtest.claim, dbtest.renew and the sweep below are the
-- reference SQL for the storage layer. The claim locks with FOR NO KEY UPDATE, which excludes other
-- claimers but not the writers of ledger, audit and outbox rows that point at the stage run through a
-- foreign key. Here both steps run in one transaction; in the engine they are two, and the compare and
-- swap and the unique index of one live attempt per stage run decide the winner (the shell races below).

DO $$
BEGIN
  PERFORM dbtest.mk_tenant(1);
  PERFORM dbtest.mk_tenant(2);
  PERFORM dbtest.mk_job(1, 1);
  PERFORM dbtest.set_status('jobs', 1, dbtest.u(1101), 'ACTIVE');
END
$$;

-- Claim one READY stage run of an ACTIVE job. Returns the new attempt id, or NULL when there is
-- nothing to claim or another claimer got there first. Step 1 runs as the system role, step 2 as the
-- tenant role with the setting for the tenant that step 1 found.
CREATE FUNCTION dbtest.claim(p_worker text) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE
  c record;
  a uuid := gen_random_uuid();
  n bigint;
BEGIN
  SET LOCAL ROLE factory_system;
  SELECT s.tenant_id, s.id, s.job_id, s.version INTO c
    FROM stage_runs s
    JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE'
   WHERE s.status = 'READY' AND s.not_before <= now()
   ORDER BY s.not_before
   LIMIT 1
   FOR NO KEY UPDATE OF s SKIP LOCKED;   -- not FOR UPDATE: see the lock mode check in scripts/db-test.sh
  RESET ROLE;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  SET LOCAL ROLE factory_app;
  PERFORM set_config('factory.tenant_id', c.tenant_id::text, true);
  UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, version = version + 1
   WHERE tenant_id = c.tenant_id AND id = c.id AND version = c.version AND status = 'READY';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 1 THEN
    RESET ROLE;
    RETURN NULL;
  END IF;
  INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
  SELECT s.tenant_id, a, s.job_id, s.id,
         (SELECT coalesce(max(x.attempt_number), 0) + 1 FROM attempts x WHERE x.tenant_id = s.tenant_id AND x.stage_run_id = s.id),
         p_worker, s.lease_epoch, now() + interval '30 seconds', now() + interval '1 hour'
    FROM stage_runs s WHERE s.tenant_id = c.tenant_id AND s.id = c.id;
  RESET ROLE;
  RETURN a;
EXCEPTION WHEN OTHERS THEN
  RESET ROLE;
  RAISE;
END
$$;

-- Renew a lease. The fence is the WHERE clause: tenant, attempt, owner, epoch, liveness, and a lease
-- that has not already expired by the database clock.
CREATE FUNCTION dbtest.renew(p_tenant uuid, p_attempt uuid, p_worker text, p_epoch bigint) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
BEGIN
  UPDATE attempts SET lease_expires_at = now() + interval '30 seconds', last_heartbeat_at = now(), version = version + 1
   WHERE tenant_id = p_tenant AND id = p_attempt AND lease_owner = p_worker AND lease_epoch = p_epoch
     AND status IN ('STARTING', 'RUNNING') AND lease_expires_at > now();
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n = 1;
END
$$;

-- The sweep, in two steps. Step 1 (system role): the tenant, id and version of every attempt whose lease
-- expired, locked FOR NO KEY UPDATE SKIP LOCKED (FOR UPDATE would block a ledger append that points at the
-- attempt). Step 2 (tenant role, once per attempt found): the compare and swap that marks it lost.
-- Returns the ids that were swept.
CREATE FUNCTION dbtest.sweep() RETURNS uuid[] LANGUAGE plpgsql AS $$
DECLARE
  c record;
  found jsonb;
  swept uuid[] := '{}';
  n bigint;
BEGIN
  SET LOCAL ROLE factory_system;
  SELECT coalesce(jsonb_agg(to_jsonb(x)), '[]'::jsonb) INTO found
    FROM (SELECT tenant_id, id, version FROM attempts
           WHERE status IN ('STARTING', 'RUNNING') AND lease_expires_at < now()
           ORDER BY lease_expires_at LIMIT 100 FOR NO KEY UPDATE SKIP LOCKED) x;
  RESET ROLE;
  FOR c IN SELECT (e ->> 'tenant_id')::uuid AS tenant_id, (e ->> 'id')::uuid AS id, (e ->> 'version')::bigint AS version
             FROM jsonb_array_elements(found) e LOOP
    SET LOCAL ROLE factory_app;
    PERFORM set_config('factory.tenant_id', c.tenant_id::text, true);
    UPDATE attempts SET status = 'LEASE_LOST', ended_at = now(), version = version + 1
     WHERE tenant_id = c.tenant_id AND id = c.id AND version = c.version
       AND status IN ('STARTING', 'RUNNING') AND lease_expires_at < now();
    GET DIAGNOSTICS n = ROW_COUNT;
    RESET ROLE;
    IF n = 1 THEN
      swept := swept || c.id;
    END IF;
  END LOOP;
  RETURN swept;
EXCEPTION WHEN OTHERS THEN
  RESET ROLE;
  RAISE;
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
