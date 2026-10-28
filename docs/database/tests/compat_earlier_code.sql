-- The statements of the code that was written for the schema after migration 14 (the claim as a swap with the epoch
-- raised and then the attempt, the lease renewal, the ledger head move with a version bump, a raised budget on a run).
-- They must keep working on every later schema. Used twice:
--
--   * `scripts/db-test.sh compat` runs this file after EACH later migration, inside a transaction that is rolled back, so
--     the same statements are tried against schema 15, 16, 17 and 18 in turn;
--   * `scripts/db-test.sh migrations` runs it once on the fully migrated database, through `\ir` in upgrade_check.sql, which
--     goes on with checks that rely on the rows it leaves: the earlier claim of run 1202 and the head move of job 1101.
--
-- The rows come from upgrade_fixture.sql, loaded on the schema of migration 14. Nothing here touches a column or a table
-- that migration 15 to 18 added: that is the point.

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
  -- A stage run edit that the earlier code made: a raised budget on a run that waits for a person.
  PERFORM dbtest.expect_ok('a raised budget on an old run that waits for a person is still accepted',
    format($q$UPDATE stage_runs SET max_attempts = 5, version = version + 1 WHERE id = %L$q$, dbtest.u(1204)), 'factory_app');
  -- The reads of the earlier code, as the application role for tenant 1.
  PERFORM dbtest.expect_eq('the earlier timeline reads still work',
    dbtest.run_as(format($q$SELECT s.id, s.status, s.version, s.lease_epoch, a.id FROM stage_runs s LEFT JOIN attempts a ON a.tenant_id = s.tenant_id AND a.stage_run_id = s.id WHERE s.tenant_id = %L AND s.job_id = %L ORDER BY s.created_at$q$, tn, dbtest.u(1101)), 'factory_app', 1) ~ '^rows=[0-9]+$', true);
END
$$;
