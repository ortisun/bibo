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
  -- Migration 2026-11-02-002400: a repository that was enabled before the project map existed has no map, so it is
  -- switched off and its version rose. Nothing else about it changed.
  PERFORM dbtest.expect_eq('every old repository is switched off and has no project map',
    (SELECT count(*) FROM repositories WHERE enabled OR project_map_commit IS NOT NULL
        OR project_map_attested_by_principal_id IS NOT NULL OR project_map_attested_at IS NOT NULL), 0::bigint);
  PERFORM dbtest.expect_eq('the version of an old repository rose by one when it was switched off',
    (SELECT min(version) FROM repositories), 2::bigint);
  PERFORM dbtest.expect_eq('an old repository keeps its name, its installation and its autonomy ceiling',
    (SELECT count(*) FROM repositories WHERE full_name = 'org1/repo' AND github_installation_id = 9001 AND autonomy_ceiling = 'L0'), 1::bigint);
  PERFORM dbtest.expect_eq('the old ledger chain still verifies against the old head', coalesce(ledger_verify_chain(dbtest.u(1), dbtest.u(1101))::text, 'ok'), 'ok');
  PERFORM dbtest.expect_eq('the old audit chain still verifies', coalesce(audit_verify_chain(dbtest.u(1))::text, 'ok'), 'ok');
  PERFORM dbtest.expect_eq('the old rows are still isolated by row-level security: a tenant 2 session sees none of them',
    dbtest.run_as('SELECT 1 FROM stage_runs', 'factory_app', 2), 'rows=0');
END
$$;

-- The statements of the earlier version, in a file of their own because `scripts/db-test.sh compat` runs them after every
-- migration in turn. Here they run once, for real: the checks below start from their effects, the earlier claim of run
-- 1202 and the head move of job 1101. (\ir reads the file from the folder of this one.)
\ir compat_earlier_code.sql

DO $$
DECLARE
  tn uuid := dbtest.u(1);
BEGIN
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
