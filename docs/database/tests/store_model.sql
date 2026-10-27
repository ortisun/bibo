-- Suite: store_model
-- Proves that the tables carry what the Store port of ports v1.1 (ADR 0014, decision 2) needs, with no value
-- invented on the way in, and that the rules the port states are rules of the data: the gate record and the
-- failing set of a stage run, the attestation of an organization admin, what a task node carries in each state,
-- the task graph (keys, cycles), and a job whose version is not disturbed by a ledger append. The recipes of the
-- operations that need only the existing tables (idempotent inserts, which key found a repeat, the platform audit
-- path, the tenant-scoped artifact read, listings) follow in the later sections of this file.
-- Every write that the engine makes is made as the application role for tenant 1.

DO $$
BEGIN
  PERFORM dbtest.mk_tenant(1);
  PERFORM dbtest.mk_tenant(2);
  PERFORM dbtest.mk_job(1, 1);
  PERFORM dbtest.set_status('jobs', 1, dbtest.u(1101), 'ACTIVE');
  INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend)
    VALUES (dbtest.u(1), dbtest.sha('report'), 10, 'application/json', 'local-fs'),
           (dbtest.u(1), dbtest.sha('plan'), 10, 'application/json', 'local-fs');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 1. The gate record: failing_set_sha256 and the BLOCKED outcome.

DO $$
DECLARE
  run uuid := dbtest.mk_stage_run(1, 1, 1);
  blocked_run uuid := dbtest.mk_stage_run(1, 1, 2, 'REPOSITORY_INTELLIGENCE');
  report text := dbtest.sha('report');
  failing text := dbtest.sha('failing set');
BEGIN
  PERFORM dbtest.set_status('stage_runs', 1, run, 'READY');
  PERFORM dbtest.set_status('stage_runs', 1, run, 'RUNNING', ', lease_epoch = lease_epoch + 1');
  PERFORM dbtest.set_status('stage_runs', 1, run, 'GATING');
  PERFORM dbtest.expect_error('failing_set_sha256 with the PASSED outcome is refused (it belongs to a FAILED gate)',
    format($q$UPDATE stage_runs SET status = 'PASSED', gate_outcome = 'PASSED', gate_report_sha256 = %L, failing_set_sha256 = %L, finished_at = now(), version = version + 1 WHERE id = %L$q$, report, failing, run),
    '23514', 'factory_app', 'stage_runs_failing_set_needs_failed_outcome');
  PERFORM dbtest.expect_error('failing_set_sha256 with no gate outcome is refused',
    format($q$UPDATE stage_runs SET status = 'FAILED', failing_set_sha256 = %L, finished_at = now(), version = version + 1 WHERE id = %L$q$, failing, run),
    '23514', 'factory_app', 'stage_runs_failing_set_needs_failed_outcome');
  PERFORM dbtest.expect_error('a failing set that is not a sha256 digest is refused',
    format($q$UPDATE stage_runs SET status = 'FAILED', gate_outcome = 'FAILED', failing_set_sha256 = 'abc', finished_at = now(), version = version + 1 WHERE id = %L$q$, run),
    '23514', 'factory_app', 'stage_runs_failing_set_hash_check');
  PERFORM dbtest.expect_error('the system role cannot write the failing set (it cannot write a stage run at all)',
    format($q$UPDATE stage_runs SET failing_set_sha256 = %L WHERE id = %L$q$, failing, run), '42501', 'factory_system');
  -- S12: GATING to FAILED with the report and the failing set, in one statement.
  PERFORM dbtest.exec(format($q$UPDATE stage_runs SET status = 'FAILED', gate_outcome = 'FAILED', gate_report_sha256 = %L, failing_set_sha256 = %L, finished_at = now(), version = version + 1 WHERE tenant_id = %L AND id = %L$q$,
                             report, failing, dbtest.u(1), run), 'factory_app');
  PERFORM dbtest.expect_eq('S12 stored the FAILED gate record with the failing set',
    (SELECT gate_outcome || ' ' || (gate_report_sha256 = report)::text || ' ' || (failing_set_sha256 = failing)::text FROM stage_runs WHERE id = run), 'FAILED true true');
  PERFORM dbtest.expect_error('a finished run keeps its failing set: it cannot be edited (INV-04)',
    format($q$UPDATE stage_runs SET failing_set_sha256 = %L, version = version + 1 WHERE id = %L$q$, dbtest.sha('other'), run), '23514', 'factory_app', 'stage_runs_terminal_is_immutable');

  -- BLOCKED records the BLOCKED outcome, from GATING (S11) and from RUNNING (S21).
  PERFORM dbtest.set_status('stage_runs', 1, blocked_run, 'READY');
  PERFORM dbtest.set_status('stage_runs', 1, blocked_run, 'RUNNING', ', lease_epoch = lease_epoch + 1');
  PERFORM dbtest.expect_error('S21 without a gate outcome is refused',
    format($q$UPDATE stage_runs SET status = 'BLOCKED', version = version + 1 WHERE id = %L$q$, blocked_run), '23514', 'factory_app', 'stage_runs_blocked_has_outcome');
  PERFORM dbtest.expect_error('S21 with another gate outcome is refused',
    format($q$UPDATE stage_runs SET status = 'BLOCKED', gate_outcome = 'FAILED', version = version + 1 WHERE id = %L$q$, blocked_run), '23514', 'factory_app', 'stage_runs_blocked_has_outcome');
  PERFORM dbtest.expect_ok('S21 with the BLOCKED outcome and its report is accepted',
    format($q$UPDATE stage_runs SET status = 'BLOCKED', gate_outcome = 'BLOCKED', gate_report_sha256 = %L, version = version + 1 WHERE id = %L$q$, report, blocked_run), 'factory_app');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. The attestation of an organization admin (ADR 0014, decision 7): who and when, both or neither, an active
-- human of the tenant, the time from the database clock.

DO $$
DECLARE
  repo uuid := dbtest.u(1001);
  human uuid := dbtest.u(1002);
  service uuid := dbtest.u(1003);
  gone uuid := dbtest.u(1004);
  attest text := 'UPDATE repositories SET bypass_attested_by_principal_id = %L, version = version + 1 WHERE tenant_id = %L AND id = %L';
BEGIN
  INSERT INTO principals (tenant_id, id, kind, github_user_id, disabled_at) VALUES (dbtest.u(1), gone, 'human', 7777, now());
  PERFORM dbtest.expect_eq('a repository starts with no attestation', (SELECT (bypass_attested_by_principal_id IS NULL AND bypass_attested_at IS NULL)::text FROM repositories WHERE id = repo), 'true');
  PERFORM dbtest.exec(format(attest, human, dbtest.u(1), repo), 'factory_app');
  PERFORM dbtest.expect_eq('the tenant role can record the attestor, and the database stamps the time',
    (SELECT (bypass_attested_by_principal_id = human AND bypass_attested_at = now())::text FROM repositories WHERE id = repo), 'true');
  PERFORM dbtest.exec(format($q$UPDATE repositories SET bypass_attested_at = '2001-01-01T00:00:00Z', version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), repo), 'factory_app');
  PERFORM dbtest.expect_eq('a time written by the caller is replaced by the stored one', (SELECT (bypass_attested_at = now())::text FROM repositories WHERE id = repo), 'true');
  PERFORM dbtest.exec(format($q$UPDATE repositories SET bypass_attested_by_principal_id = NULL, bypass_attested_at = now(), version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), repo), 'factory_app');
  PERFORM dbtest.expect_eq('clearing the attestor clears the time, whatever the caller wrote for it',
    (SELECT (bypass_attested_by_principal_id IS NULL AND bypass_attested_at IS NULL)::text FROM repositories WHERE id = repo), 'true');
  PERFORM dbtest.expect_error('a service principal cannot attest', format(attest, service, dbtest.u(1), repo), '23514', 'factory_app', 'repositories_attestor_is_an_active_human');
  PERFORM dbtest.expect_error('a disabled human cannot attest', format(attest, gone, dbtest.u(1), repo), '23514', 'factory_app', 'repositories_attestor_is_an_active_human');
  PERFORM dbtest.expect_error('a principal of another tenant cannot attest (the tenant is part of the key)', format(attest, dbtest.u(2002), dbtest.u(1), repo), '23514', 'factory_app', 'repositories_attestor_is_an_active_human');
  PERFORM dbtest.expect_error('a principal that does not exist cannot attest', format(attest, dbtest.u(99999), dbtest.u(1), repo), '23514', 'factory_app', 'repositories_attestor_is_an_active_human');
  PERFORM dbtest.expect_error('the attestor and the time must be both set or both null (with the triggers off, the CHECK alone)',
    format($q$SET LOCAL session_replication_role = replica; UPDATE repositories SET bypass_attested_by_principal_id = %L WHERE id = %L$q$, human, repo), '23514', NULL, 'repositories_bypass_attestation_pair');
  -- The time stays when something else about the repository changes.
  SET LOCAL session_replication_role = replica;
  UPDATE repositories SET bypass_attested_by_principal_id = human, bypass_attested_at = '2020-01-01T00:00:00Z', version = version + 1 WHERE id = repo;
  SET LOCAL session_replication_role = origin;
  PERFORM dbtest.exec(format($q$UPDATE repositories SET default_branch = 'trunk', version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), repo), 'factory_app');
  PERFORM dbtest.expect_eq('the time of an attestation does not move when another column changes',
    (SELECT (bypass_attested_at = '2020-01-01T00:00:00Z'::timestamptz)::text FROM repositories WHERE id = repo), 'true');
  PERFORM dbtest.expect_error('the system role cannot read or write the attestation', format($q$SELECT bypass_attested_at FROM repositories$q$), '42501', 'factory_system');
  PERFORM dbtest.expect_error('and cannot write it', format(attest, human, dbtest.u(1), repo), '42501', 'factory_system');
  PERFORM dbtest.expect_ok('a repository can be inserted already attested by an active human',
    format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch, bypass_attested_by_principal_id)
              VALUES (%L, %L, 9001, 8099, 'org1/other', 'main', %L)$q$, dbtest.u(1), dbtest.u(1098), human), 'factory_app');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. Task nodes: what each state carries (TaskNodeEffects), and the graph (insert_task_graph).

DO $$
DECLARE
  run uuid := dbtest.mk_stage_run(1, 1, 3, 'IMPLEMENTATION');
  attempt uuid := dbtest.u(1301);
  plan text := dbtest.sha('plan');
  move text := 'UPDATE task_nodes SET %s, version = version + 1 WHERE tenant_id = ''' || dbtest.u(1)::text || ''' AND id = %L';
  commit_sha text := repeat('a', 40);
BEGIN
  PERFORM dbtest.set_status('stage_runs', 1, run, 'READY');
  PERFORM dbtest.set_status('stage_runs', 1, run, 'RUNNING', ', lease_epoch = lease_epoch + 1');
  INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
    VALUES (dbtest.u(1), attempt, dbtest.u(1101), run, 1, 'worker-s', 1, now() + interval '30 seconds', now() + interval '1 hour');
  -- The graph is created in one step: the nodes, then the edges.
  INSERT INTO task_nodes (tenant_id, id, job_id, stage_run_id, task_key, plan_sha256) VALUES
    (dbtest.u(1), dbtest.u(1401), dbtest.u(1101), run, 't-001', plan),
    (dbtest.u(1), dbtest.u(1402), dbtest.u(1101), run, 't-002', plan),
    (dbtest.u(1), dbtest.u(1403), dbtest.u(1101), run, 't-003', plan);
  INSERT INTO task_node_dependencies (tenant_id, stage_run_id, task_node_id, depends_on_task_node_id) VALUES
    (dbtest.u(1), run, dbtest.u(1402), dbtest.u(1401)), (dbtest.u(1), run, dbtest.u(1403), dbtest.u(1402));
  PERFORM dbtest.expect_eq('the graph was created: three nodes, two edges',
    (SELECT count(*) FROM task_nodes WHERE stage_run_id = run) || ':' || (SELECT count(*) FROM task_node_dependencies WHERE stage_run_id = run), '3:2');

  PERFORM dbtest.expect_error('a task key already used in the stage run is refused (DuplicateTaskKey)',
    format($q$INSERT INTO task_nodes (tenant_id, id, job_id, stage_run_id, task_key, plan_sha256) VALUES (%L, %L, %L, %L, 't-001', %L)$q$, dbtest.u(1), dbtest.u(1499), dbtest.u(1101), run, plan),
    '23505', 'factory_app', 'task_nodes_tenant_id_stage_run_id_task_key_key');
  PERFORM dbtest.expect_error('an edge that closes a cycle is refused (DependencyCycle)',
    format($q$INSERT INTO task_node_dependencies (tenant_id, stage_run_id, task_node_id, depends_on_task_node_id) VALUES (%L, %L, %L, %L)$q$, dbtest.u(1), run, dbtest.u(1401), dbtest.u(1403)),
    '23514', 'factory_app', 'task_node_dependencies_acyclic');
  PERFORM dbtest.expect_error('two edges of one statement that together close a cycle are refused: the second sees the first',
    format($q$INSERT INTO task_nodes (tenant_id, id, job_id, stage_run_id, task_key, plan_sha256) VALUES (%1$L, %5$L, %2$L, %3$L, 't-004', %4$L), (%1$L, %6$L, %2$L, %3$L, 't-005', %4$L);
              INSERT INTO task_node_dependencies (tenant_id, stage_run_id, task_node_id, depends_on_task_node_id) VALUES (%1$L, %3$L, %5$L, %6$L), (%1$L, %3$L, %6$L, %5$L)$q$,
           dbtest.u(1), dbtest.u(1101), run, plan, dbtest.u(1404), dbtest.u(1405)), '23514', 'factory_app', 'task_node_dependencies_acyclic');
  PERFORM dbtest.expect_error('a node that depends on itself is refused',
    format($q$INSERT INTO task_node_dependencies (tenant_id, stage_run_id, task_node_id, depends_on_task_node_id) VALUES (%L, %L, %L, %L)$q$, dbtest.u(1), run, dbtest.u(1401), dbtest.u(1401)),
    '23514', 'factory_app');
  PERFORM dbtest.expect_error('a plan that is not an artifact of the tenant is refused (the plan must be indexed first)',
    format($q$INSERT INTO task_nodes (tenant_id, id, job_id, stage_run_id, task_key, plan_sha256) VALUES (%L, %L, %L, %L, 't-009', %L)$q$, dbtest.u(1), dbtest.u(1498), dbtest.u(1101), run, dbtest.sha('unindexed')),
    '23503', 'factory_app');

  -- T01 and T02: the node starts with the attempt that took it.
  PERFORM dbtest.exec(format(move, 'status = ''READY''', dbtest.u(1401)), 'factory_app');
  PERFORM dbtest.expect_error('T02 without the attempt is refused', format(move, 'status = ''RUNNING''', dbtest.u(1401)), '23514', 'factory_app', 'task_nodes_running_has_attempt');
  PERFORM dbtest.exec(format(move, format('status = ''RUNNING'', current_attempt_id = %L', attempt), dbtest.u(1401)), 'factory_app');
  PERFORM dbtest.expect_error('T05 that leaves the attempt on the node is refused (the node is READY again and belongs to nobody)',
    format(move, 'status = ''READY''', dbtest.u(1401)), '23514', 'factory_app', 'task_nodes_idle_has_no_attempt');
  PERFORM dbtest.expect_ok('T05 that clears the attempt is accepted', format(move, 'status = ''READY'', current_attempt_id = NULL', dbtest.u(1401)), 'factory_app');
  PERFORM dbtest.expect_ok('T04 that clears the attempt is accepted: FAILED, no attempt', format(move, 'status = ''FAILED'', current_attempt_id = NULL', dbtest.u(1401)), 'factory_app');
  PERFORM dbtest.expect_error('T04 that keeps the attempt is refused', format(move, 'status = ''FAILED''', dbtest.u(1401)), '23514', 'factory_app', 'task_nodes_idle_has_no_attempt');
  -- T03: the commit that finished the node.
  PERFORM dbtest.expect_error('T03 without a commit is refused',
    format(move, 'status = ''SUCCEEDED'', finished_at = now()', dbtest.u(1401)), '23514', 'factory_app', 'task_nodes_commit_iff_succeeded');
  PERFORM dbtest.expect_ok('T03 with the commit is accepted',
    format(move, format('status = ''SUCCEEDED'', commit_sha = %L, finished_at = now()', commit_sha), dbtest.u(1401)), 'factory_app');
  PERFORM dbtest.expect_error('a commit on a node that is not SUCCEEDED is refused',
    format(move, format('commit_sha = %L', commit_sha), dbtest.u(1402)), '23514', 'factory_app', 'task_nodes_commit_iff_succeeded');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. A ledger append does not disturb the job's version. The head pointer moves with an append; a transition
-- of the job compares the version it read before the append, in the same transaction or in another.

DO $$
DECLARE
  tn uuid := dbtest.u(1);
  job uuid := dbtest.u(1101);
  run uuid := dbtest.u(1201);   -- the FAILED stage run of section 1; any run of the job may own ledger entries
  v bigint := (SELECT version FROM jobs WHERE id = dbtest.u(1101));
  h1 text;
  h2 text;
BEGIN
  h1 := dbtest.append_entry(1, job, run, 1);
  PERFORM dbtest.exec(format($q$UPDATE jobs SET ledger_head_sequence = 1, ledger_head_hash = %L WHERE tenant_id = %L AND id = %L$q$, h1, tn, job), 'factory_app');
  PERFORM dbtest.expect_eq('an append moves the head and leaves the version of the job where it was',
    (SELECT ledger_head_sequence || ':' || (version = v)::text FROM jobs WHERE id = job), '1:true');
  PERFORM dbtest.expect_eq('so a transition that read the version before the append still matches (one row), in the same transaction or another',
    dbtest.run_as(format($q$UPDATE jobs SET status = 'PAUSED', version = version + 1 WHERE tenant_id = %L AND id = %L AND version = %s$q$, tn, job, v), 'factory_app', 1), 'rows=1');
  PERFORM dbtest.expect_error('a status change still has to raise the version by one',
    format($q$UPDATE jobs SET status = 'PAUSED' WHERE tenant_id = %L AND id = %L$q$, tn, job), '23514', 'factory_app', 'jobs_version_bump');
  PERFORM dbtest.expect_error('and by exactly one',
    format($q$UPDATE jobs SET status = 'PAUSED', version = version + 2 WHERE tenant_id = %L AND id = %L$q$, tn, job), '23514', 'factory_app', 'jobs_version_bump');

  h2 := dbtest.append_entry(1, job, run, 2);
  PERFORM dbtest.expect_error('the head may skip the bump only when it is the only thing that moves (here the policy hash moves too)',
    format($q$UPDATE jobs SET ledger_head_sequence = 2, ledger_head_hash = %L, policy_hash = %L WHERE tenant_id = %L AND id = %L$q$, h2, dbtest.sha('policy'), tn, job),
    '23514', 'factory_app', 'jobs_version_bump');
  PERFORM dbtest.expect_ok('the head and the status together, with the version raised by one, as before',
    format($q$UPDATE jobs SET status = 'PAUSED', ledger_head_sequence = 2, ledger_head_hash = %L, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, h2, tn, job), 'factory_app');
  PERFORM dbtest.expect_ok('and the head alone with the version raised by one is still accepted (older callers)',
    format($q$UPDATE jobs SET ledger_head_sequence = 2, ledger_head_hash = %L, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, h2, tn, job), 'factory_app');
  PERFORM dbtest.expect_error('an update that changes nothing and does not raise the version is refused',
    format($q$UPDATE jobs SET ledger_head_sequence = ledger_head_sequence WHERE tenant_id = %L AND id = %L$q$, tn, job), '23514', 'factory_app', 'jobs_version_bump');
  PERFORM dbtest.expect_error('the head never moves back, with or without a version bump',
    format($q$UPDATE jobs SET ledger_head_sequence = 0, ledger_head_hash = NULL, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, tn, job), '23514', 'factory_app', 'jobs_ledger_head_only_moves_forward');
  PERFORM dbtest.exec(format($q$UPDATE jobs SET ledger_head_sequence = 2, ledger_head_hash = %L WHERE tenant_id = %L AND id = %L$q$, h2, tn, job), 'factory_app');
  PERFORM dbtest.expect_eq('after the second append the chain verifies and the version is still the one read at the start',
    coalesce(ledger_verify_chain(tn, job)::text, 'ok') || ' ' || (SELECT (version = v)::text FROM jobs WHERE id = job), 'ok true');
END
$$;
