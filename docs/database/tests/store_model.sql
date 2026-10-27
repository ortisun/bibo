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

-- ---------------------------------------------------------------------------------------------
-- 5. insert_job, idempotent by id and content and found by its origin (JobOrigin). The statement is
-- INSERT ... ON CONFLICT DO NOTHING RETURNING id. No row back means "already there, or a key clashed": the adapter
-- then reads the job by id, then by the origin, and compares the content. Neither read finds a job when the clash
-- was on correlation_id alone.

DO $$
DECLARE
  tn uuid := dbtest.u(1);
  ins text := $q$INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level, pipeline_scope, correlation_id, idempotency_key, webhook_delivery_id)
                  VALUES (%L, %L, %L, %L, 'production', 'L1', ARRAY['INTAKE', 'SPECIFICATION'], %L, %L, %L) ON CONFLICT DO NOTHING RETURNING id$q$;
BEGIN
  INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, github_installation_id, body_sha256)
    VALUES (tn, dbtest.u(3001), 'delivery-3001', 'issues', 9001, dbtest.sha('body 3001'));
  PERFORM dbtest.exec(format(ins, tn, dbtest.u(3101), dbtest.u(1001), dbtest.u(1002), dbtest.u(3201), 'key-3101', NULL), 'factory_app');
  PERFORM dbtest.exec(format(ins, tn, dbtest.u(3102), dbtest.u(1001), dbtest.u(1002), dbtest.u(3202), NULL, dbtest.u(3001)), 'factory_app');
  PERFORM dbtest.expect_eq('insert_job: a new job is inserted in RECEIVED at version 1 with the clock of the database',
    (SELECT status || ':' || version || ':' || (created_at = now())::text FROM jobs WHERE id = dbtest.u(3101)), 'RECEIVED:1:true');
  PERFORM dbtest.expect_eq('insert_job: the same id and content again gives no row (a replay)',
    dbtest.run_as(format(ins, tn, dbtest.u(3101), dbtest.u(1001), dbtest.u(1002), dbtest.u(3201), 'key-3101', NULL), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_eq('insert_job: another id with the same idempotency key gives no row, and the key finds the first job',
    dbtest.run_as(format(ins, tn, dbtest.u(3103), dbtest.u(1001), dbtest.u(1002), dbtest.u(3203), 'key-3101', NULL), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_eq('the first job by its idempotency key', (SELECT id FROM jobs WHERE tenant_id = tn AND idempotency_key = 'key-3101'), dbtest.u(3101));
  PERFORM dbtest.expect_eq('insert_job: another id for the same webhook delivery gives no row, and the delivery finds the first job',
    dbtest.run_as(format(ins, tn, dbtest.u(3104), dbtest.u(1001), dbtest.u(1002), dbtest.u(3204), NULL, dbtest.u(3001)), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_eq('the first job by its delivery', (SELECT id FROM jobs WHERE tenant_id = tn AND webhook_delivery_id = dbtest.u(3001)), dbtest.u(3102));
  PERFORM dbtest.expect_eq('insert_job: the same id with other content also gives no row, and the content comparison tells it apart',
    dbtest.run_as(format(ins, tn, dbtest.u(3101), dbtest.u(1098), dbtest.u(1002), dbtest.u(3201), 'key-3101', NULL), 'factory_app', 1)
    || ' ' || (SELECT ((repository_id, requester_principal_id, correlation_id) IS NOT DISTINCT FROM (dbtest.u(1098), dbtest.u(1002), dbtest.u(3201)))::text FROM jobs WHERE id = dbtest.u(3101)),
    'rows=0 false');
  PERFORM dbtest.expect_eq('a clash on the correlation id alone gives no row and no job is found by id or origin',
    dbtest.run_as(format(ins, tn, dbtest.u(3105), dbtest.u(1001), dbtest.u(1002), dbtest.u(3201), 'key-3105', NULL), 'factory_app', 1)
    || ' ' || (SELECT count(*) FROM jobs WHERE id = dbtest.u(3105) OR idempotency_key = 'key-3105'),
    'rows=0 0');
  PERFORM dbtest.expect_error('a job for a repository of another tenant is refused (the composite key)',
    format(replace(ins, ' ON CONFLICT DO NOTHING RETURNING id', ''), tn, dbtest.u(3106), dbtest.u(2001), dbtest.u(1002), dbtest.u(3206), NULL, NULL), '23503', 'factory_app');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 6. record_delivery: INSERT ... ON CONFLICT DO NOTHING RETURNING id, and when nothing comes back, one probe says which
-- key found the repeat (DuplicateOf). The delivery id wins over the body, and the body over the semantic key.

CREATE FUNCTION dbtest.record_delivery(p_id uuid, p_delivery text, p_body text, p_semantic text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  inserted uuid;
  found text;
BEGIN
  PERFORM dbtest.become('factory_app', 1);
  INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, github_installation_id, body_sha256, semantic_key)
    VALUES (dbtest.u(1), p_id, p_delivery, 'issues', 9001, dbtest.sha(p_body), CASE WHEN p_semantic IS NULL THEN NULL ELSE dbtest.sha(p_semantic) END)
    ON CONFLICT DO NOTHING RETURNING id INTO inserted;
  IF inserted IS NOT NULL THEN
    RESET ROLE;
    RETURN 'recorded';
  END IF;
  SELECT CASE WHEN d.delivery_id = p_delivery THEN 'delivery_id' WHEN d.body_sha256 = dbtest.sha(p_body) THEN 'body' ELSE 'semantic' END INTO found
    FROM webhook_deliveries d
   WHERE d.tenant_id = dbtest.u(1) AND (d.delivery_id = p_delivery OR d.body_sha256 = dbtest.sha(p_body) OR d.semantic_key = dbtest.sha(p_semantic))
   ORDER BY (d.delivery_id = p_delivery) DESC, (d.body_sha256 = dbtest.sha(p_body)) DESC LIMIT 1;
  RESET ROLE;
  RETURN 'duplicate:' || found;
END
$$;

DO $$
BEGIN
  PERFORM dbtest.expect_eq('record_delivery: a new delivery is recorded', dbtest.record_delivery(dbtest.u(3301), 'delivery-3301', 'body A', 'semantic A'), 'recorded');
  PERFORM dbtest.expect_eq('the same delivery id is a duplicate by delivery_id, not an error', dbtest.record_delivery(dbtest.u(3302), 'delivery-3301', 'body B', 'semantic B'), 'duplicate:delivery_id');
  PERFORM dbtest.expect_eq('the same body under a fresh delivery id is a duplicate by body', dbtest.record_delivery(dbtest.u(3303), 'delivery-3303', 'body A', 'semantic C'), 'duplicate:body');
  PERFORM dbtest.expect_eq('the same semantic key under a fresh id and body is a duplicate by semantic key', dbtest.record_delivery(dbtest.u(3304), 'delivery-3304', 'body D', 'semantic A'), 'duplicate:semantic');
  PERFORM dbtest.expect_eq('a delivery with no semantic key is recorded, and a second with none is not a duplicate of the first',
    dbtest.record_delivery(dbtest.u(3305), 'delivery-3305', 'body E', NULL) || ' ' || dbtest.record_delivery(dbtest.u(3306), 'delivery-3306', 'body F', NULL), 'recorded recorded');
  PERFORM dbtest.expect_eq('only the recorded deliveries are stored (plus the one of section 5)', (SELECT count(*) FROM webhook_deliveries WHERE tenant_id = dbtest.u(1)), 4::bigint);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 7. record_original_request and insert_stage_run: idempotent by id; another id for the same revision, or for the same
-- (job, kind, run number), is a unique violation that the adapter maps to IdReusedWithDifferentContent.

DO $$
DECLARE
  tn uuid := dbtest.u(1);
  job uuid := dbtest.u(3101);
  req text := $q$INSERT INTO original_requests (tenant_id, id, job_id, revision, source, request_text, content_sha256)
                  VALUES (%L, %L, %L, %s, 'github_issue', %L, 'sha256:' || encode(sha256(convert_to(%L, 'UTF8')), 'hex')) ON CONFLICT (tenant_id, id) DO NOTHING RETURNING id$q$;
  run text := $q$INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number, max_attempts) VALUES (%L, %L, %L, 'SPECIFICATION', %s, 3) ON CONFLICT (tenant_id, id) DO NOTHING RETURNING id$q$;
BEGIN
  PERFORM dbtest.exec(format(req, tn, dbtest.u(3401), job, 1, 'Add a retry.', 'Add a retry.'), 'factory_app');
  PERFORM dbtest.expect_eq('record_original_request: a replay of the same id gives no row', dbtest.run_as(format(req, tn, dbtest.u(3401), job, 1, 'Add a retry.', 'Add a retry.'), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_error('another id for the same revision is a unique violation (IdReusedWithDifferentContent)',
    format(req, tn, dbtest.u(3402), job, 1, 'Something else.', 'Something else.'), '23505', 'factory_app', 'original_requests_tenant_id_job_id_revision_key');
  PERFORM dbtest.exec(format(req, tn, dbtest.u(3403), job, 2, 'Add a retry, with a limit.', 'Add a retry, with a limit.'), 'factory_app');
  PERFORM dbtest.expect_eq('get_original_request: the latest revision is the highest, and an older one stays readable',
    (SELECT request_text FROM original_requests WHERE tenant_id = tn AND job_id = job ORDER BY revision DESC LIMIT 1) || ' | ' || (SELECT request_text FROM original_requests WHERE tenant_id = tn AND job_id = job AND revision = 1),
    'Add a retry, with a limit. | Add a retry.');
  PERFORM dbtest.expect_error('an original request cannot be edited (no update privilege)', format($q$UPDATE original_requests SET request_text = 'x' WHERE id = %L$q$, dbtest.u(3401)), '42501', 'factory_app');
  PERFORM dbtest.expect_error('a hash that is not the hash of the text is refused', format($q$INSERT INTO original_requests (tenant_id, id, job_id, revision, source, request_text, content_sha256) VALUES (%L, %L, %L, 3, 'api', 'text', %L)$q$, tn, dbtest.u(3404), job, dbtest.sha('other')),
    '23514', 'factory_app', 'original_requests_hash_matches_text');

  PERFORM dbtest.exec(format(run, tn, dbtest.u(3501), job, 1), 'factory_app');
  PERFORM dbtest.expect_eq('insert_stage_run: a new run is PENDING at epoch 0 and version 1', (SELECT status || ':' || lease_epoch || ':' || version FROM stage_runs WHERE id = dbtest.u(3501)), 'PENDING:0:1');
  PERFORM dbtest.expect_eq('insert_stage_run: a replay of the same id gives no row', dbtest.run_as(format(run, tn, dbtest.u(3501), job, 1), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_error('another id for the same kind and run number of the job is a unique violation',
    format(run, tn, dbtest.u(3502), job, 1), '23505', 'factory_app', 'stage_runs_tenant_id_job_id_stage_kind_run_number_key');
  PERFORM dbtest.expect_ok('a rework adds the next run number', format(run, tn, dbtest.u(3503), job, 2), 'factory_app');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 8. record_audit and record_platform_audit. Idempotent by event id: ON CONFLICT (tenant_id, event_id) DO NOTHING takes no
-- sequence number, so a replay leaves no gap. An event that belongs to no job is normal. The platform tenant holds the
-- events of no tenant, written by the tenant role with the platform setting; nothing else sees them.

CREATE FUNCTION dbtest.audit_sql(p_tenant uuid, p_event uuid, p_job uuid DEFAULT NULL, p_run uuid DEFAULT NULL, p_action text DEFAULT 'approval.recorded', p_reason text DEFAULT 'The decision was recorded.') RETURNS text LANGUAGE sql AS $$
  SELECT format($q$INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, job_id, stage_run_id, correlation_id)
                   VALUES (%L, %L, 'service', 'workflow.engine', %L, 'job:x', 'record', %L, %L, %L, %L, %L) ON CONFLICT (tenant_id, event_id) DO NOTHING RETURNING sequence$q$,
                p_tenant, p_event, p_action, p_reason, dbtest.sha('policy'), p_job, p_run, dbtest.u(3601))
$$;

DO $$
DECLARE
  tn uuid := dbtest.u(1);
  platform uuid := '00000000-0000-0000-0000-000000000001';
  head bigint;
BEGIN
  PERFORM dbtest.exec(dbtest.audit_sql(tn, dbtest.u(3701)), 'factory_app');
  head := (SELECT max(sequence) FROM audit_events WHERE tenant_id = tn);
  PERFORM dbtest.expect_eq('record_audit: an event with no job is stored (FR-002: a rejected issue belongs to no job)',
    (SELECT (job_id IS NULL)::text FROM audit_events WHERE event_id = dbtest.u(3701)), 'true');
  PERFORM dbtest.expect_eq('record_audit: a replay of the same event id gives no row', dbtest.run_as(dbtest.audit_sql(tn, dbtest.u(3701)), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.exec(dbtest.audit_sql(tn, dbtest.u(3702), dbtest.u(3101)), 'factory_app');
  PERFORM dbtest.expect_eq('and the replay took no sequence number: the next event follows the head, and the chain verifies',
    (SELECT sequence FROM audit_events WHERE event_id = dbtest.u(3702)) - head || ' ' || coalesce(audit_verify_chain(tn)::text, 'ok'), '1 ok');
  PERFORM dbtest.expect_eq('the stored event can be compared with a replay (same fields means a true replay)',
    (SELECT ((actor_type, actor_id, action, subject, decision, reason, job_id, stage_run_id, correlation_id) IS NOT DISTINCT FROM ('service', 'workflow.engine', 'approval.recorded', 'job:x', 'record', 'The decision was recorded.', NULL::uuid, NULL::uuid, dbtest.u(3601)))::text FROM audit_events WHERE event_id = dbtest.u(3701)), 'true');
  PERFORM dbtest.expect_error('a stage run without a job is refused', dbtest.audit_sql(tn, dbtest.u(3703), NULL, dbtest.u(1201)), '23514', 'factory_app', 'audit_events_stage_run_needs_job');
  PERFORM dbtest.expect_error('a job of another tenant is refused (the composite key)', dbtest.audit_sql(tn, dbtest.u(3704), dbtest.u(2101)), '23503', 'factory_app');

  -- The platform path: the setting is the platform tenant's, the event has no job, the actor is anonymous.
  PERFORM dbtest.exec(replace(dbtest.audit_sql(platform, dbtest.u(3801), NULL, NULL, 'webhook.rejected', 'The signature did not verify.'), '''service'', ''workflow.engine''', '''anonymous'', ''webhook'''), 'factory_app', -1);
  PERFORM dbtest.exec(replace(dbtest.audit_sql(platform, dbtest.u(3802), NULL, NULL, 'webhook.rejected', 'The installation is unknown.'), '''service'', ''workflow.engine''', '''anonymous'', ''webhook'''), 'factory_app', -1);
  PERFORM dbtest.expect_eq('record_platform_audit: two events land in the platform tenant chain, numbered 1 and 2, and the chain verifies',
    (SELECT string_agg(sequence::text, ',' ORDER BY sequence) FROM audit_events WHERE tenant_id = platform) || ' ' || coalesce(audit_verify_chain(platform)::text, 'ok'), '1,2 ok');
  PERFORM dbtest.expect_eq('record_platform_audit: a replay of the same event id gives no row',
    dbtest.run_as(replace(dbtest.audit_sql(platform, dbtest.u(3801), NULL, NULL, 'webhook.rejected', 'The signature did not verify.'), '''service'', ''workflow.engine''', '''anonymous'', ''webhook'''), 'factory_app', -1), 'rows=0');
  PERFORM dbtest.expect_eq('a tenant 1 session does not see the platform events', dbtest.run_as(format('SELECT 1 FROM audit_events WHERE tenant_id = %L', platform), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_eq('and a tenant 2 session does not either', dbtest.run_as('SELECT 1 FROM audit_events WHERE action = ''webhook.rejected''', 'factory_app', 2), 'rows=0');
  PERFORM dbtest.expect_error('a platform event cannot name a job: the platform tenant has none (the composite key)', dbtest.audit_sql(platform, dbtest.u(3803), dbtest.u(1101)), '23503', 'factory_app', NULL, NULL, -1);
  PERFORM dbtest.expect_error('a tenant 1 session cannot write an event for the platform tenant (the policy)',
    dbtest.audit_sql(platform, dbtest.u(3804)), '42501', 'factory_app', NULL, NULL, 1);
  PERFORM dbtest.expect_error('a platform session cannot write an event for tenant 1 either', dbtest.audit_sql(tn, dbtest.u(3805)), '42501', 'factory_app', NULL, NULL, -1);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 9. The tenant-scoped artifact read (ArtifactStore::get and exists consult the tenant's own index row) and index_artifact,
-- idempotent by hash.

DO $$
DECLARE
  h text := dbtest.sha('report');
  idx text := $q$INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend, created_by_job_id, created_by_stage_run_id)
                  VALUES (%L, %L, 10, 'application/json', 'local-fs', %L, %L) ON CONFLICT (tenant_id, content_sha256) DO NOTHING RETURNING content_sha256$q$;
BEGIN
  PERFORM dbtest.expect_eq('exists: the tenant that indexed the hash finds it', dbtest.run_as(format('SELECT 1 FROM artifacts WHERE tenant_id = %L AND content_sha256 = %L', dbtest.u(1), h), 'factory_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('exists: another tenant gets nothing for the same hash, as for a hash nobody holds',
    dbtest.run_as(format('SELECT 1 FROM artifacts WHERE tenant_id = %L AND content_sha256 = %L', dbtest.u(2), h), 'factory_app', 2)
    || ' ' || dbtest.run_as(format('SELECT 1 FROM artifacts WHERE tenant_id = %L AND content_sha256 = %L', dbtest.u(2), dbtest.sha('nobody holds this')), 'factory_app', 2), 'rows=0 rows=0');
  PERFORM dbtest.expect_eq('and a lookup that forgot the tenant still returns nothing to tenant 2 (the policy answers for the missing WHERE)',
    dbtest.run_as(format('SELECT 1 FROM artifacts WHERE content_sha256 = %L', h), 'factory_app', 2), 'rows=0');
  PERFORM dbtest.expect_eq('index_artifact: a replay for the same hash gives no row', dbtest.run_as(format(idx, dbtest.u(1), h, NULL, NULL), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_eq('index_artifact: tenant 2 can index the same hash for itself, and then finds it, without learning that tenant 1 holds it',
    dbtest.run_as(format(idx, dbtest.u(2), h, NULL, NULL), 'factory_app', 2), 'rows=1');
  PERFORM dbtest.expect_ok('index_artifact: the job and stage run that made it are recorded together',
    format(idx, dbtest.u(1), dbtest.sha('new artifact'), dbtest.u(1101), dbtest.u(1201)), 'factory_app');
  PERFORM dbtest.expect_error('index_artifact: a stage run of another job is refused (the composite key)',
    format(idx, dbtest.u(1), dbtest.sha('new artifact 2'), dbtest.u(3101), dbtest.u(1201)), '23503', 'factory_app');
  PERFORM dbtest.expect_error('index_artifact: a job without a stage run is refused',
    format(idx, dbtest.u(1), dbtest.sha('new artifact 3'), dbtest.u(1101), NULL), '23514', 'factory_app');
  PERFORM dbtest.expect_error('index_artifact: the size is required (an artifact of unknown size is not indexed)',
    format($q$INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend) VALUES (%L, %L, NULL, 'text/plain', 'local-fs')$q$, dbtest.u(1), dbtest.sha('no size')), '23502', 'factory_app');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 10. Principals, run artifacts, approvals and the witness.

DO $$
DECLARE
  tn uuid := dbtest.u(1);
  head text := repeat('d', 40);
  appr text := $q$INSERT INTO approvals (tenant_id, id, job_id, stage_run_id, decision, approver_principal_id, approver_github_user_id, approver_designation, allowlist_version_hash, policy_hash, reason, channel, expires_at, pr_head_sha, tree_hash, base_sha, evidence_manifest_hash, spec_version)
                   SELECT p.tenant_id, %L, %L, %L, %L, p.id, p.github_user_id, 'approver', %L, %L, 'Reviewed the evidence.', 'cli', now() + interval '72 hours', %L, %L, %L, %L, 1
                     FROM principals p WHERE p.tenant_id = %L AND p.id = %L AND p.kind = 'human' AND p.disabled_at IS NULL
                   ON CONFLICT (tenant_id, id) DO NOTHING RETURNING id$q$;
  link text := $q$INSERT INTO stage_run_artifacts (tenant_id, job_id, stage_run_id, direction, role, content_sha256) VALUES (%L, %L, %L, %L, %L, %L) ON CONFLICT (tenant_id, stage_run_id, direction, role) DO NOTHING RETURNING role$q$;
BEGIN
  -- Principals.
  PERFORM dbtest.expect_ok('insert_principal: a human with a GitHub user id', format($q$INSERT INTO principals (tenant_id, id, kind, github_user_id, login) VALUES (%L, %L, 'human', 8801, 'carol')$q$, tn, dbtest.u(3901)), 'factory_app');
  PERFORM dbtest.expect_error('insert_principal: a GitHub user id already recorded for the tenant under another id is a unique violation (ExternalReferenceTaken)',
    format($q$INSERT INTO principals (tenant_id, id, kind, github_user_id) VALUES (%L, %L, 'human', 7001)$q$, tn, dbtest.u(3902)), '23505', 'factory_app', 'principals_tenant_id_github_user_id_key');
  PERFORM dbtest.expect_ok('the same GitHub user id in another tenant is allowed', format($q$INSERT INTO principals (tenant_id, id, kind, github_user_id) VALUES (%L, %L, 'human', 7001)$q$, dbtest.u(2), dbtest.u(3903)), 'factory_app', 2);
  PERFORM dbtest.expect_error('a human without a GitHub id is refused', format($q$INSERT INTO principals (tenant_id, id, kind) VALUES (%L, %L, 'human')$q$, tn, dbtest.u(3904)), '23514', 'factory_app');
  PERFORM dbtest.expect_error('a service with a GitHub id is refused', format($q$INSERT INTO principals (tenant_id, id, kind, github_user_id) VALUES (%L, %L, 'service', 9)$q$, tn, dbtest.u(3905)), '23514', 'factory_app');
  PERFORM dbtest.expect_eq('find_principal_by_github_user: by the numeric id, within the tenant',
    (SELECT id FROM principals WHERE tenant_id = tn AND github_user_id = 7001), dbtest.u(1002));

  -- Run artifacts.
  PERFORM dbtest.exec(format(link, tn, dbtest.u(1101), dbtest.u(1201), 'input', 'spec', dbtest.sha('report')), 'factory_app');
  PERFORM dbtest.expect_eq('link_stage_run_artifact: the same role and hash again gives no row (a repeat)', dbtest.run_as(format(link, tn, dbtest.u(1101), dbtest.u(1201), 'input', 'spec', dbtest.sha('report')), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_eq('and the same role with another hash gives no row either; the comparison tells it apart (IdReusedWithDifferentContent)',
    dbtest.run_as(format(link, tn, dbtest.u(1101), dbtest.u(1201), 'input', 'spec', dbtest.sha('plan')), 'factory_app', 1)
    || ' ' || (SELECT (content_sha256 = dbtest.sha('plan'))::text FROM stage_run_artifacts WHERE stage_run_id = dbtest.u(1201) AND direction = 'input' AND role = 'spec'), 'rows=0 false');
  PERFORM dbtest.exec(format(link, tn, dbtest.u(1101), dbtest.u(1201), 'input', 'human-answer-1', dbtest.sha('plan')), 'factory_app');
  PERFORM dbtest.expect_eq('a human answer is an input with the role human-answer-<n>, and the listing is oldest first',
    (SELECT string_agg(role, ',' ORDER BY created_at, role) FROM stage_run_artifacts WHERE tenant_id = tn AND stage_run_id = dbtest.u(1201)), 'human-answer-1,spec');
  PERFORM dbtest.expect_eq('stage_runs_consuming: the runs of the job that read an artifact',
    (SELECT string_agg(stage_run_id::text, ',') FROM stage_run_artifacts WHERE tenant_id = tn AND job_id = dbtest.u(1101) AND content_sha256 = dbtest.sha('report') AND direction = 'input'), dbtest.u(1201)::text);
  PERFORM dbtest.expect_error('an artifact the tenant has not indexed cannot be linked (the composite key)',
    format(link, tn, dbtest.u(1101), dbtest.u(1201), 'output', 'summary', dbtest.sha('not indexed')), '23503', 'factory_app');

  -- Approvals.
  PERFORM dbtest.exec(format(appr, dbtest.u(4001), dbtest.u(1101), dbtest.u(1201), 'approve', dbtest.sha('allowlist'), dbtest.sha('policy'), head, repeat('e', 40), repeat('f', 40), dbtest.sha('manifest'), tn, dbtest.u(1002)), 'factory_app');
  PERFORM dbtest.expect_eq('record_approval: the GitHub user id comes from the principal and the expiry from the database clock (72 hours)',
    (SELECT approver_github_user_id || ' ' || (expires_at = now() + interval '72 hours')::text FROM approvals WHERE id = dbtest.u(4001)), '7001 true');
  PERFORM dbtest.expect_eq('record_approval: a replay of the same id gives no row',
    dbtest.run_as(format(appr, dbtest.u(4001), dbtest.u(1101), dbtest.u(1201), 'approve', dbtest.sha('allowlist'), dbtest.sha('policy'), head, repeat('e', 40), repeat('f', 40), dbtest.sha('manifest'), tn, dbtest.u(1002)), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_error('record_approval: a second approve of the same approver for the same head under another id is a unique violation (IdReusedWithDifferentContent)',
    format(appr, dbtest.u(4002), dbtest.u(1101), dbtest.u(1201), 'approve', dbtest.sha('allowlist'), dbtest.sha('policy'), head, repeat('e', 40), repeat('f', 40), dbtest.sha('manifest'), tn, dbtest.u(1002)),
    '23505', 'factory_app', 'approvals_one_decision_per_head');
  PERFORM dbtest.expect_eq('record_approval: a service principal makes no row (the SELECT finds no human), so nothing is recorded',
    dbtest.run_as(format(appr, dbtest.u(4003), dbtest.u(1101), dbtest.u(1201), 'approve', dbtest.sha('allowlist'), dbtest.sha('policy'), head, repeat('e', 40), repeat('f', 40), dbtest.sha('manifest'), tn, dbtest.u(1003)), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_eq('valid_approvals: only the approve decision bound to the head, not invalidated and not expired',
    (SELECT count(*) FROM approvals WHERE tenant_id = tn AND job_id = dbtest.u(1101) AND decision = 'approve' AND pr_head_sha = head AND invalidated_at IS NULL AND expires_at > now())
    || ':' || (SELECT count(*) FROM approvals WHERE tenant_id = tn AND job_id = dbtest.u(1101) AND decision = 'approve' AND pr_head_sha = repeat('0', 40) AND invalidated_at IS NULL AND expires_at > now()), '1:0');
  PERFORM dbtest.exec(format($q$UPDATE approvals SET invalidated_at = now(), invalidation_reason = 'new_commit' WHERE tenant_id = %L AND job_id = %L AND invalidated_at IS NULL AND expires_at > now()$q$, tn, dbtest.u(1101)), 'factory_app');
  PERFORM dbtest.expect_eq('invalidate_approvals: marks the valid ones; the approval no longer counts', (SELECT count(*) FROM approvals WHERE tenant_id = tn AND job_id = dbtest.u(1101) AND decision = 'approve' AND pr_head_sha = head AND invalidated_at IS NULL AND expires_at > now()), 0::bigint);
  PERFORM dbtest.expect_eq('and repeating it changes no row', dbtest.run_as(format($q$UPDATE approvals SET invalidated_at = now(), invalidation_reason = 'new_commit' WHERE tenant_id = %L AND job_id = %L AND invalidated_at IS NULL AND expires_at > now()$q$, tn, dbtest.u(1101)), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_ok('a decision with no head can repeat (a person pauses, resumes and pauses again): the uniqueness is per head',
    format($q$INSERT INTO approvals (tenant_id, id, job_id, stage_run_id, decision, approver_principal_id, approver_github_user_id, approver_designation, allowlist_version_hash, policy_hash, reason, channel, expires_at)
              VALUES (%1$L, %2$L, %3$L, %4$L, 'pause', %5$L, 7001, 'operator', %6$L, %6$L, 'Pause.', 'cli', now() + interval '1 hour'),
                     (%1$L, %7$L, %3$L, %4$L, 'pause', %5$L, 7001, 'operator', %6$L, %6$L, 'Pause again.', 'cli', now() + interval '1 hour')$q$,
           tn, dbtest.u(4004), dbtest.u(1101), dbtest.u(1201), dbtest.u(1002), dbtest.sha('allowlist'), dbtest.u(4005)), 'factory_app');

  -- The witness (Store::committed): a row of the outbox, or of the audit log, by id and tenant.
  PERFORM dbtest.expect_eq('committed: an audit record is found by its id for its tenant and not for another',
    (SELECT count(*) FROM audit_events WHERE tenant_id = tn AND event_id = dbtest.u(3701)) || ':' || dbtest.run_as(format('SELECT 1 FROM audit_events WHERE tenant_id = %L AND event_id = %L', dbtest.u(2), dbtest.u(3701)), 'factory_app', 2), '1:rows=0');
END
$$;
