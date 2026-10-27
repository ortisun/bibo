-- After the upgrade from migration 14 to the newest. The rows of upgrade_fixture.sql are still there (the shell compares
-- their fingerprints). This file checks what the shell cannot: the new columns hold their defaults for old rows,
-- the new reference rows exist, the old rows still pass their own verifiers, and the statements that the code of
-- the earlier version made still work on the new schema (version N and N + 1 on one schema).

DO $$
BEGIN
  PERFORM dbtest.expect_eq('the new state machine rows exist (S21 and S22)',
    (SELECT count(*) FROM state_machine_transitions WHERE machine = 'stage_run' AND transition_id IN ('S21', 'S22')), 2::bigint);
  PERFORM dbtest.expect_eq('every old stage run has the default window and no failing set',
    (SELECT count(*) FROM stage_runs WHERE attempts_before_last_answer <> 0 OR failing_set_sha256 IS NOT NULL), 0::bigint);
  PERFORM dbtest.expect_eq('every old repository has no attestation', (SELECT count(*) FROM repositories WHERE bypass_attested_by_principal_id IS NOT NULL OR bypass_attested_at IS NOT NULL), 0::bigint);
  PERFORM dbtest.expect_eq('the old ledger chain still verifies against the old head', coalesce(ledger_verify_chain(dbtest.u(1), dbtest.u(1101))::text, 'ok'), 'ok');
  PERFORM dbtest.expect_eq('the old audit chain still verifies', coalesce(audit_verify_chain(dbtest.u(1))::text, 'ok'), 'ok');
  PERFORM dbtest.expect_eq('the old rows are still isolated by row-level security: a tenant 2 session sees none of them',
    dbtest.run_as('SELECT 1 FROM stage_runs', 'factory_app', 2), 'rows=0');
END
$$;

-- The statements of the earlier version, as the application role for tenant 1.
DO $$
DECLARE
  tn uuid := dbtest.u(1);
BEGIN
  -- The claim as it was: a swap with the epoch raised, and the attempt, with a limit that counts every attempt.
  PERFORM dbtest.exec(format($q$UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, version = version + 1 WHERE tenant_id = %L AND id = %L AND version = 2 AND status = 'READY';
                               INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
                               VALUES (%L, %L, %L, %L, 1, 'worker-old', 1, now() + interval '30 seconds', now() + interval '1 hour')$q$,
                             tn, dbtest.u(1202), tn, dbtest.u(1303), dbtest.u(1101), dbtest.u(1202)), 'factory_app');
  PERFORM dbtest.expect_eq('the earlier claim still works on the new schema', (SELECT status || ':' || lease_epoch FROM stage_runs WHERE id = dbtest.u(1202)), 'RUNNING:1');
  -- The renewal and the sweep as they were.
  PERFORM dbtest.expect_eq('the earlier renewal still works',
    dbtest.run_as(format($q$UPDATE attempts SET lease_expires_at = now() + interval '30 seconds', last_heartbeat_at = now(), version = version + 1 WHERE tenant_id = %L AND id = %L AND lease_owner = 'worker-old' AND lease_epoch = 1 AND status IN ('STARTING', 'RUNNING') AND lease_expires_at > now()$q$, tn, dbtest.u(1303)), 'factory_app', 1), 'rows=1');
  -- A ledger entry appended, with the head moved in the same update and the version raised by one, as the earlier code did.
  PERFORM dbtest.append_entry(1, dbtest.u(1101), dbtest.u(1201), 3);
  PERFORM dbtest.expect_eq('the earlier head move with a version bump is still accepted',
    dbtest.run_as(format($q$UPDATE jobs SET ledger_head_sequence = 3, ledger_head_hash = %L, version = version + 1 WHERE tenant_id = %L AND id = %L$q$,
                         (SELECT entry_hash FROM ledger_entries WHERE job_id = dbtest.u(1101) AND sequence = 3), tn, dbtest.u(1101)), 'factory_app', 1), 'rows=1');
  -- A stage run edit that the earlier code made: a raised budget on a READY run, and a retry with a back-off.
  PERFORM dbtest.expect_ok('a raised budget on an old run that waits for a person is still accepted',
    format($q$UPDATE stage_runs SET max_attempts = 5, version = version + 1 WHERE id = %L$q$, dbtest.u(1204)), 'factory_app');
  -- New code on an old row: a person answers (S13) on the WAITING_FOR_HUMAN run of the earlier version, and the new
  -- start_attempt sequence (job share-locked, run locked, swap, attempt) starts its second attempt.
  PERFORM dbtest.exec(format($q$UPDATE stage_runs SET status = 'READY', version = version + 1 WHERE tenant_id = %L AND id = %L$q$, tn, dbtest.u(1204)), 'factory_app');
  PERFORM dbtest.expect_eq('S13 on a row of the earlier version records that its one attempt came before the answer',
    (SELECT attempts_before_last_answer FROM stage_runs WHERE id = dbtest.u(1204)), 1);
  PERFORM dbtest.expect_ok('the new claim sequence starts the second attempt of that old row',
    format($q$SELECT status FROM jobs WHERE tenant_id = %1$L AND id = %2$L FOR SHARE;
              SELECT status FROM stage_runs WHERE tenant_id = %1$L AND id = %3$L FOR NO KEY UPDATE;
              UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, version = version + 1 WHERE tenant_id = %1$L AND id = %3$L AND status = 'READY';
              INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
              VALUES (%1$L, %4$L, %2$L, %3$L, 2, 'worker-new', 2, now() + interval '30 seconds', now() + interval '1 hour')$q$,
           tn, dbtest.u(1101), dbtest.u(1204), dbtest.u(1304)), 'factory_app');
END
$$;
